use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A file-backed editor for the entries PowerMap owns in a hosts file.
#[derive(Debug, Clone)]
pub struct HostsStore {
    path: PathBuf,
}

/// Errors produced while editing a hosts file.
#[derive(Debug)]
pub enum HostsError {
    Io(io::Error),
    InvalidDomain,
    Unsupported,
}

impl fmt::Display for HostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "hosts file operation failed: {error}"),
            Self::InvalidDomain => write!(f, "domain must not contain line breaks"),
            Self::Unsupported => write!(f, "the system hosts file is unsupported on this platform"),
        }
    }
}

impl std::error::Error for HostsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidDomain | Self::Unsupported => None,
        }
    }
}

impl From<io::Error> for HostsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl HostsStore {
    /// Returns the native system hosts-file path for this platform.
    pub fn default_path() -> Result<PathBuf, HostsError> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            Ok(PathBuf::from("/etc/hosts"))
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(HostsError::Unsupported)
        }
    }

    /// Opens an editor for the native system hosts file.
    pub fn system() -> Result<Self, HostsError> {
        Ok(Self::at(Self::default_path()?))
    }

    /// Opens an editor for the hosts file at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Adds PowerMap's loopback entry, replacing only its exact existing entry.
    pub fn ensure_loopback(&self, domain: &str) -> Result<(), HostsError> {
        self.edit(domain, true)
    }

    /// Removes only PowerMap's exact loopback entry for `domain`.
    pub fn remove_loopback(&self, domain: &str) -> Result<(), HostsError> {
        self.edit(domain, false)
    }

    /// Returns whether this store contains PowerMap's exact managed entry.
    pub fn has_loopback(&self, domain: &str) -> Result<bool, HostsError> {
        validate_domain(domain)?;
        let entry = entry_for(domain);
        Ok(fs::read_to_string(&self.path)?
            .lines()
            .any(|line| line == entry))
    }

    fn edit(&self, domain: &str, ensure: bool) -> Result<(), HostsError> {
        validate_domain(domain)?;
        // This advisory sidecar lock serializes cooperating PowerMap processes across
        // the read-modify-atomic-replace transaction.
        let _lock = acquire_edit_lock(&self.path)?;
        let original = fs::read_to_string(&self.path)?;
        let entry = entry_for(domain);
        let mut updated = remove_exact_entry(&original, &entry);

        if ensure {
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(&entry);
            updated.push('\n');
        }

        atomic_replace(&self.path, updated.as_bytes())
    }
}

fn hosts_lock_path(path: &Path) -> Result<PathBuf, HostsError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        HostsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hosts file path has no filename",
        ))
    })?;
    Ok(parent.join(format!(".{}.powermap.lock", file_name.to_string_lossy())))
}

fn acquire_edit_lock(path: &Path) -> Result<File, HostsError> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(hosts_lock_path(path)?)?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;

        loop {
            let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(HostsError::Io(error));
        }
    }

    Ok(lock)
}

fn validate_domain(domain: &str) -> Result<(), HostsError> {
    if domain.contains(['\n', '\r']) {
        return Err(HostsError::InvalidDomain);
    }
    Ok(())
}

fn entry_for(domain: &str) -> String {
    format!("127.0.0.1 {domain} # PowerMap domain mapping: {domain}")
}

fn remove_exact_entry(contents: &str, entry: &str) -> String {
    let mut kept = String::with_capacity(contents.len());
    for line in contents.split_inclusive('\n') {
        let bare_line = line.strip_suffix('\n').unwrap_or(line);
        if bare_line != entry {
            kept.push_str(line);
        }
    }
    kept
}

fn atomic_replace(path: &Path, contents: &[u8]) -> Result<(), HostsError> {
    let metadata = fs::metadata(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        HostsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hosts file path has no filename",
        ))
    })?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.powermap-{}-{counter}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> Result<(), HostsError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.set_permissions(metadata.permissions())?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{HostsStore, acquire_edit_lock};

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::path::PathBuf;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    use super::HostsError;

    fn contents(file: &tempfile::NamedTempFile) -> String {
        std::fs::read_to_string(file.path()).unwrap()
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn default_path_uses_etc_hosts_on_supported_platforms() {
        assert_eq!(
            HostsStore::default_path().unwrap(),
            PathBuf::from("/etc/hosts")
        );
        assert_eq!(
            HostsStore::system().unwrap().path,
            PathBuf::from("/etc/hosts")
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn default_path_reports_unsupported_platform() {
        assert!(matches!(
            HostsStore::default_path(),
            Err(HostsError::Unsupported)
        ));
        assert!(matches!(HostsStore::system(), Err(HostsError::Unsupported)));
    }

    #[test]
    fn ensure_and_remove_only_own_marked_entry() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "127.0.0.1 existing.local\n").unwrap();
        let store = HostsStore::at(file.path());

        store.ensure_loopback("ai-router.dl-aiot.com").unwrap();
        store.remove_loopback("ai-router.dl-aiot.com").unwrap();

        assert_eq!(
            std::fs::read_to_string(file.path()).unwrap(),
            "127.0.0.1 existing.local\n"
        );
    }

    #[test]
    fn ensure_is_idempotent() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let store = HostsStore::at(file.path());

        store.ensure_loopback("ai-router.dl-aiot.com").unwrap();
        store.ensure_loopback("ai-router.dl-aiot.com").unwrap();

        assert_eq!(
            contents(&file),
            "127.0.0.1 ai-router.dl-aiot.com # PowerMap domain mapping: ai-router.dl-aiot.com\n"
        );
    }

    #[test]
    fn remove_preserves_unrelated_entry_for_same_domain() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "10.0.0.2 ai-router.dl-aiot.com\n127.0.0.1 ai-router.dl-aiot.com # PowerMap domain mapping: ai-router.dl-aiot.com\n",
        )
        .unwrap();
        let store = HostsStore::at(file.path());

        store.remove_loopback("ai-router.dl-aiot.com").unwrap();

        assert_eq!(contents(&file), "10.0.0.2 ai-router.dl-aiot.com\n");
    }

    #[test]
    fn remove_preserves_malformed_marked_line() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "127.0.0.1 ai-router.dl-aiot.com # PowerMap domain mapping: other.example\n",
        )
        .unwrap();
        let store = HostsStore::at(file.path());

        store.remove_loopback("ai-router.dl-aiot.com").unwrap();

        assert_eq!(
            contents(&file),
            "127.0.0.1 ai-router.dl-aiot.com # PowerMap domain mapping: other.example\n"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn cooperative_lock_serializes_concurrent_powermap_edits() {
        use std::sync::mpsc;
        use std::time::Duration;

        let file = tempfile::NamedTempFile::new().unwrap();
        let lock = acquire_edit_lock(file.path()).unwrap();
        let path = file.path().to_path_buf();
        let (done_tx, done_rx) = mpsc::channel();
        let edit = std::thread::spawn(move || {
            let result = HostsStore::at(path).ensure_loopback("api.example.test");
            done_tx.send(result.is_ok()).unwrap();
        });

        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(lock);
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        edit.join().unwrap();
        assert_eq!(
            contents(&file),
            "127.0.0.1 api.example.test # PowerMap domain mapping: api.example.test\n"
        );
    }
}
