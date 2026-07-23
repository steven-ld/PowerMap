//! Read-only process metadata for the local management API.

use std::path::Path;

use serde::Serialize;

/// A snapshot of the process hosting the management API.
#[derive(Debug, Serialize)]
pub struct RuntimeInfo {
    pub pid: u32,
    pub executable_path: Option<String>,
    pub config_path: String,
    pub platform: Platform,
    pub supervisor: Supervisor,
    pub privilege: Privilege,
}

#[derive(Debug, Serialize)]
pub struct Platform {
    pub os: &'static str,
    pub architecture: &'static str,
    pub family: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Supervisor {
    pub kind: SupervisorKind,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorKind {
    None,
    Systemd,
    Launchd,
    WindowsTaskScheduler,
}

#[derive(Debug, Serialize)]
pub struct Privilege {
    pub level: PrivilegeLevel,
    /// Unix effective user ID. Windows does not expose a comparable ID here.
    pub uid: Option<u32>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeLevel {
    Root,
    Administrator,
    User,
    Unknown,
}

/// Collects local process metadata without spawning commands or reading configuration contents.
pub fn snapshot(config_path: &Path) -> RuntimeInfo {
    RuntimeInfo {
        pid: std::process::id(),
        executable_path: std::env::current_exe()
            .ok()
            .map(|path| path.to_string_lossy().into_owned()),
        config_path: config_path.to_string_lossy().into_owned(),
        platform: Platform {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            family: std::env::consts::FAMILY,
        },
        supervisor: Supervisor {
            kind: detect_supervisor(|name| std::env::var_os(name).is_some()),
        },
        privilege: current_privilege(),
    }
}

fn detect_supervisor(has_env: impl Fn(&str) -> bool) -> SupervisorKind {
    if ["INVOCATION_ID", "NOTIFY_SOCKET", "JOURNAL_STREAM"]
        .iter()
        .any(|name| has_env(name))
    {
        SupervisorKind::Systemd
    } else if ["LAUNCH_JOB_LABEL", "XPC_SERVICE_NAME"]
        .iter()
        .any(|name| has_env(name))
    {
        SupervisorKind::Launchd
    } else if ["TASK_NAME", "TASK_INSTANCE_ID"]
        .iter()
        .any(|name| has_env(name))
    {
        // Task Scheduler does not promise these variables for every task, so this is deliberately
        // best-effort rather than a claim that an absent marker means an interactive process.
        SupervisorKind::WindowsTaskScheduler
    } else {
        SupervisorKind::None
    }
}

#[cfg(unix)]
fn current_privilege() -> Privilege {
    let uid = unsafe { libc::geteuid() };
    Privilege {
        level: if uid == 0 {
            PrivilegeLevel::Root
        } else {
            PrivilegeLevel::User
        },
        uid: Some(uid),
    }
}

#[cfg(windows)]
fn current_privilege() -> Privilege {
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process: *mut std::ffi::c_void,
            access: u32,
            token: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn GetTokenInformation(
            token: *mut std::ffi::c_void,
            information_class: u32,
            information: *mut std::ffi::c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }

    let mut token = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0;
    if !opened {
        return Privilege {
            level: PrivilegeLevel::Unknown,
            uid: None,
        };
    }
    let mut elevated = 0_u32;
    let mut returned = 0_u32;
    let queried = unsafe {
        GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            (&mut elevated as *mut u32).cast(),
            std::mem::size_of_val(&elevated) as u32,
            &mut returned,
        )
    } != 0;
    unsafe { CloseHandle(token) };
    Privilege {
        level: if queried && elevated != 0 {
            PrivilegeLevel::Administrator
        } else if queried {
            PrivilegeLevel::User
        } else {
            PrivilegeLevel::Unknown
        },
        uid: None,
    }
}

#[cfg(not(any(unix, windows)))]
fn current_privilege() -> Privilege {
    Privilege {
        level: PrivilegeLevel::Unknown,
        uid: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_includes_process_and_config_metadata() {
        let path = Path::new("/tmp/powermap.toml");
        let info = snapshot(path);

        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.config_path, path.to_string_lossy());
        assert!(!info.platform.os.is_empty());
        assert!(!info.platform.architecture.is_empty());
        assert!(!info.platform.family.is_empty());
    }

    #[test]
    fn supervisor_detection_recognizes_service_markers() {
        assert_eq!(
            detect_supervisor(|name| name == "NOTIFY_SOCKET"),
            SupervisorKind::Systemd
        );
        assert_eq!(
            detect_supervisor(|name| name == "LAUNCH_JOB_LABEL"),
            SupervisorKind::Launchd
        );
        assert_eq!(
            detect_supervisor(|name| name == "TASK_NAME"),
            SupervisorKind::WindowsTaskScheduler
        );
        assert_eq!(detect_supervisor(|_| false), SupervisorKind::None);
    }
}
