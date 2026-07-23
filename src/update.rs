use std::{
    cmp::Ordering,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// A downloadable asset published with a GitHub Release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub url: String,
}

impl ReleaseAsset {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
        }
    }
}

pub struct SelectedAssets<'a> {
    pub archive: &'a ReleaseAsset,
    pub checksum: &'a ReleaseAsset,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub html_url: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    pub assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UpdateStatus {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_url: String,
    pub notes: String,
    pub install: InstallGuidance,
}

/// The upgrade handoff appropriate to the current runtime environment.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct InstallGuidance {
    pub kind: String,
    pub label: String,
    pub command: Option<String>,
}

pub const RELEASES_API: &str = "https://api.github.com/repos/steven-ld/PowerMap/releases/latest";
const STARTUP_BACKUP_ENV: &str = "POWERMAP_UPDATE_BACKUP";
const MAX_RELEASE_BYTES: usize = 100 * 1024 * 1024;

/// Coordinates one pending update with the graceful HTTP shutdown that precedes `exec`.
#[derive(Clone)]
pub struct UpdateCoordinator {
    pending: Arc<Mutex<Option<PreparedUpdate>>>,
    cancel: CancellationToken,
}

struct PreparedUpdate {
    version: String,
    current: PathBuf,
    staged: PathBuf,
    // Keeps the staged binary alive until it has been renamed into place.
    _staging_dir: tempfile::TempDir,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueuedUpdate {
    pub latest_version: String,
}

impl UpdateCoordinator {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            pending: Arc::new(Mutex::new(None)),
            cancel,
        }
    }

    /// Download and validate the update while the old process is still serving requests.
    pub async fn queue_latest(&self) -> Result<QueuedUpdate> {
        let mut pending = self.pending.lock().await;
        if pending.is_some() {
            bail!("更新正在准备重启")
        }
        let prepared = prepare_latest_update().await?;
        let queued = QueuedUpdate {
            latest_version: prepared.version.clone(),
        };
        *pending = Some(prepared);
        Ok(queued)
    }

    /// Let the response flush before closing listeners; `restart_if_queued` runs after shutdown.
    pub fn request_restart(&self) {
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            cancel.cancel();
        });
    }

    pub async fn restart_if_queued(&self) -> Result<bool> {
        let Some(prepared) = self.pending.lock().await.take() else {
            return Ok(false);
        };
        let backup = replace_binary(&prepared.current, &prepared.staged)?;
        tracing::info!(version = %prepared.version, binary = %prepared.current.display(), "已安装更新，准备重启");

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            let error = std::process::Command::new(&prepared.current)
                .args(std::env::args_os().skip(1))
                .env(STARTUP_BACKUP_ENV, &backup)
                .exec();
            restore_binary(&prepared.current, &backup)
                .context("无法启动新版本，已尝试恢复旧版本")?;
            Err(error).context("无法重启到新版本")
        }
        #[cfg(not(unix))]
        {
            restore_binary(&prepared.current, &backup)?;
            bail!("当前平台暂不支持进程内安装更新，请使用安装脚本")
        }
    }
}

/// Remove the fallback binary after the new process has remained alive through its startup gate.
pub fn confirm_startup() -> Result<()> {
    let Some(backup) = std::env::var_os(STARTUP_BACKUP_ENV) else {
        return Ok(());
    };
    let backup = PathBuf::from(backup);
    if backup.exists() {
        std::fs::remove_file(&backup)
            .with_context(|| format!("清理已确认的旧版本备份失败: {}", backup.display()))?;
    }
    // The environment is process-global. This runs before PowerMap starts worker tasks.
    unsafe { std::env::remove_var(STARTUP_BACKUP_ENV) };
    Ok(())
}

/// Restore and re-exec the prior binary when the new version fails during its startup gate.
pub fn rollback_failed_start(error: anyhow::Error) -> Result<()> {
    let Some(backup) = std::env::var_os(STARTUP_BACKUP_ENV) else {
        return Err(error);
    };
    let backup = PathBuf::from(backup);
    if !backup.exists() {
        return Err(error);
    }
    let current = std::env::current_exe().context("无法定位失败的新版本二进制")?;
    restore_binary(&current, &backup).context("新版本启动失败，恢复旧版本也失败")?;

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let restart_error = std::process::Command::new(&current)
            .args(std::env::args_os().skip(1))
            .env_remove(STARTUP_BACKUP_ENV)
            .exec();
        Err(anyhow::anyhow!(
            "新版本启动失败 ({error})；已恢复旧版本但无法重启 ({restart_error})"
        ))
    }
    #[cfg(not(unix))]
    {
        Err(anyhow::anyhow!("新版本启动失败，已恢复旧版本: {error}"))
    }
}

async fn prepare_latest_update() -> Result<PreparedUpdate> {
    let release = fetch_latest_release().await?;
    let status = update_status(env!("CARGO_PKG_VERSION"), &release)?;
    if !status.update_available {
        bail!("当前已是最新版本 v{}", status.current_version)
    }
    let target = release_target(std::env::consts::OS, std::env::consts::ARCH)?;
    let assets: Vec<_> = release
        .assets
        .iter()
        .map(|asset| ReleaseAsset::new(&asset.name, &asset.browser_download_url))
        .collect();
    let selected = select_release_assets(&assets, target)?;
    let archive = download_asset(&selected.archive.url).await?;
    let checksum = String::from_utf8(download_asset(&selected.checksum.url).await?)
        .context("校验文件不是 UTF-8 文本")?;
    let expected = parse_checksum(&checksum, &selected.archive.name)?;
    verify_sha256(&archive, &expected)?;

    let current = std::env::current_exe().context("无法找到当前 PowerMap 二进制")?;
    let parent = current
        .parent()
        .ok_or_else(|| anyhow::anyhow!("当前 PowerMap 二进制没有父目录"))?;
    let staging_dir = tempfile::Builder::new()
        .prefix(".powermap-update-")
        .tempdir_in(parent)
        .context("无法在当前二进制目录创建更新临时目录；请确认目录可写")?;
    let staged = unpack_archive(&archive, staging_dir.path())?;
    Ok(PreparedUpdate {
        version: status.latest_version,
        current,
        staged,
        _staging_dir: staging_dir,
    })
}

async fn download_asset(url: &str) -> Result<Vec<u8>> {
    let response = reqwest::Client::builder()
        .user_agent(format!("powermap/{}", env!("CARGO_PKG_VERSION")))
        .build()?
        .get(url)
        .send()
        .await
        .context("下载更新文件失败")?
        .error_for_status()
        .context("读取更新文件失败")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RELEASE_BYTES as u64)
    {
        bail!("更新文件超过允许大小")
    }
    let bytes = response.bytes().await.context("读取更新文件内容失败")?;
    if bytes.len() > MAX_RELEASE_BYTES {
        bail!("更新文件超过允许大小")
    }
    Ok(bytes.to_vec())
}

fn release_target(os: &str, arch: &str) -> Result<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("windows", _) => bail!("Windows 暂不支持进程内升级，请使用 install.ps1"),
        _ => bail!("当前平台 {arch}-{os} 暂无可用更新包"),
    }
}

pub async fn fetch_latest_release() -> Result<GithubRelease> {
    let response = reqwest::Client::builder()
        .user_agent(format!("powermap/{}", env!("CARGO_PKG_VERSION")))
        .build()?
        .get(RELEASES_API)
        .send()
        .await
        .context("请求 GitHub Release 失败")?
        .error_for_status()
        .context("读取 GitHub Release 失败")?;
    let release: GithubRelease = response.json().await.context("解析 Release 元数据失败")?;
    if release.draft || release.prerelease {
        bail!("最新 Release 不是稳定正式版")
    }
    Ok(release)
}

pub fn update_status(current_version: &str, release: &GithubRelease) -> Result<UpdateStatus> {
    if release.draft || release.prerelease {
        bail!("只接受稳定正式版 Release")
    }
    Ok(UpdateStatus {
        current_version: current_version.to_string(),
        latest_version: release.tag_name.trim_start_matches('v').to_string(),
        update_available: compare_versions(current_version, &release.tag_name)?.is_lt(),
        release_url: release.html_url.clone(),
        notes: release.body.clone(),
        install: install_guidance(
            std::env::consts::OS,
            is_docker_runtime(),
            is_systemd_service(),
            is_macos_system_install(),
            &release.tag_name,
        ),
    })
}

fn is_docker_runtime() -> bool {
    Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|cgroup| cgroup.contains("docker") || cgroup.contains("containerd"))
            .unwrap_or(false)
}

fn is_systemd_service() -> bool {
    std::env::var_os("INVOCATION_ID").is_some() && Path::new("/run/systemd/system").exists()
}

fn is_macos_system_install() -> bool {
    std::env::consts::OS == "macos"
        && std::env::current_exe()
            .map(|path| path.starts_with("/usr/local/bin/"))
            .unwrap_or(false)
}

fn install_guidance(
    os: &str,
    docker: bool,
    systemd: bool,
    macos_system_install: bool,
    release_tag: &str,
) -> InstallGuidance {
    if docker {
        return InstallGuidance {
            kind: "docker".into(),
            label: "复制 Docker 升级命令".into(),
            command: Some(format!(
                "POWERMAP_TAG={release_tag} docker compose pull && POWERMAP_TAG={release_tag} docker compose up -d"
            )),
        };
    }
    if os == "windows" {
        return InstallGuidance {
            kind: "windows".into(),
            label: "复制 Windows 升级命令".into(),
            command: Some(format!(
                "iwr https://raw.githubusercontent.com/steven-ld/PowerMap/{release_tag}/scripts/install.ps1 -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File .\\install.ps1 -RestartTask"
            )),
        };
    }
    if systemd {
        return InstallGuidance {
            kind: "systemd".into(),
            label: "复制 systemd 升级命令".into(),
            command: Some(format!(
                "curl -fsSL https://raw.githubusercontent.com/steven-ld/PowerMap/{release_tag}/scripts/install.sh | sudo env POWERMAP_VERSION={release_tag} INSTALL_DIR=/usr/local/bin POWERMAP_RESTART_SERVICE=1 sh"
            )),
        };
    }
    if os == "macos" && macos_system_install {
        return InstallGuidance {
            kind: "launchd".into(),
            label: "复制 LaunchAgent 升级命令".into(),
            command: Some(format!(
                "curl -fsSL https://raw.githubusercontent.com/steven-ld/PowerMap/{release_tag}/scripts/install.sh | sudo env POWERMAP_VERSION={release_tag} INSTALL_DIR=/usr/local/bin sh && launchctl kickstart -k gui/$(id -u)/com.powermap"
            )),
        };
    }
    InstallGuidance {
        kind: "in_app".into(),
        label: "下载并重启".into(),
        command: None,
    }
}

/// Compare stable `major.minor.patch` release versions. Git tags may start with `v`.
pub fn compare_versions(current: &str, candidate: &str) -> Result<Ordering> {
    fn parse(version: &str) -> Result<[u64; 3]> {
        let version = version.trim().strip_prefix('v').unwrap_or(version.trim());
        if version.contains('-') || version.contains('+') {
            bail!("仅支持稳定版更新，收到 {version}");
        }
        let parts: Vec<_> = version.split('.').collect();
        if parts.len() != 3 {
            bail!("版本格式无效: {version}");
        }
        let mut parsed = [0; 3];
        for (index, part) in parts.iter().enumerate() {
            parsed[index] = part
                .parse()
                .map_err(|_| anyhow::anyhow!("版本格式无效: {version}"))?;
        }
        Ok(parsed)
    }

    Ok(parse(current)?.cmp(&parse(candidate)?))
}

/// Choose the checksum pair for the current platform and reject incomplete releases.
pub fn select_release_assets<'a>(
    assets: &'a [ReleaseAsset],
    target: &str,
) -> Result<SelectedAssets<'a>> {
    let archive_name = format!("powermap-{target}.tar.gz");
    let checksum_name = format!("powermap-{target}.sha256");
    let archive = assets
        .iter()
        .find(|asset| asset.name == archive_name)
        .ok_or_else(|| anyhow::anyhow!("Release 缺少 {archive_name}"))?;
    let checksum = assets
        .iter()
        .find(|asset| asset.name == checksum_name)
        .ok_or_else(|| anyhow::anyhow!("Release 缺少 {checksum_name}"))?;
    Ok(SelectedAssets { archive, checksum })
}

/// Extract the SHA-256 digest belonging to one release archive.
pub fn parse_checksum(contents: &str, archive_name: &str) -> Result<String> {
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(digest) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        if name.trim_start_matches('*') != archive_name {
            continue;
        }
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("{archive_name} 的 SHA-256 格式无效");
        }
        return Ok(digest.to_ascii_lowercase());
    }
    bail!("校验文件未包含 {archive_name}")
}

pub fn verify_sha256(bytes: &[u8], expected: &str) -> Result<()> {
    let expected = expected.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("预期 SHA-256 格式无效");
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !crate::tunnel::token_ok(&actual, &expected) {
        bail!("下载文件的 SHA-256 校验失败");
    }
    Ok(())
}

/// Safely unpack the only file an in-app update is allowed to install.
///
/// Release archives are intentionally treated as untrusted input even after a checksum check:
/// callers may be behind a compromised proxy and a release asset can be malformed. We never use
/// `Archive::unpack`, because it would honor paths and link types from the archive.
pub fn unpack_archive(archive: &[u8], target_dir: &Path) -> Result<PathBuf> {
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().context("读取更新归档失败")?;
    let binary_path = target_dir.join("powermap");
    let mut found = false;

    for entry in entries {
        let mut entry = entry.context("读取更新归档条目失败")?;
        let path = entry.path().context("读取更新归档路径失败")?;
        if !path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            bail!("更新归档包含不安全的路径: {}", path.display());
        }
        let entry_type = entry.header().entry_type();
        if path.as_ref() != Path::new("powermap") {
            if entry_type.is_file() || entry_type.is_dir() {
                continue;
            }
            bail!("更新归档包含不安全的文件类型: {}", path.display());
        }
        if !entry_type.is_file() {
            bail!("更新归档中的 powermap 必须是常规文件");
        }
        if found {
            bail!("更新归档包含重复的 powermap 文件");
        }
        if entry.header().size().context("读取更新二进制大小失败")? > MAX_RELEASE_BYTES as u64
        {
            bail!("更新二进制超过允许大小");
        }
        std::fs::create_dir_all(target_dir).context("创建更新临时目录失败")?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&binary_path)
            .context("创建更新二进制文件失败")?;
        std::io::copy(&mut entry, &mut output).context("解压更新二进制失败")?;
        output.sync_all().context("落盘更新二进制失败")?;
        found = true;
    }

    if !found {
        bail!("更新归档未包含 powermap 二进制文件");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755))
            .context("设置更新二进制权限失败")?;
    }
    Ok(binary_path)
}

/// Atomically put a verified staged binary in place, retaining the running binary for rollback.
/// The staged file must be created next to `current` so both renames stay on one filesystem.
pub fn replace_binary(current: &Path, staged: &Path) -> Result<PathBuf> {
    let name = current
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("无法确定当前二进制文件名"))?;
    let backup = current.with_file_name(format!(".{name}.powermap-backup-{}", std::process::id()));
    if backup.exists() {
        bail!("存在未清理的更新备份: {}", backup.display());
    }
    std::fs::rename(current, &backup)
        .with_context(|| format!("备份当前二进制失败: {}", current.display()))?;
    if let Err(error) = std::fs::rename(staged, current) {
        let rollback = std::fs::rename(&backup, current);
        return match rollback {
            Ok(()) => Err(error).context("替换更新二进制失败，已恢复旧版本"),
            Err(rollback_error) => Err(anyhow::anyhow!(
                "替换更新二进制失败 ({error})，且恢复旧版本也失败 ({rollback_error}); 备份位于 {}",
                backup.display()
            )),
        };
    }
    Ok(backup)
}

/// Restore the prior executable after a replacement or restart failure.
pub fn restore_binary(current: &Path, backup: &Path) -> Result<()> {
    if current.exists() {
        std::fs::remove_file(current)
            .with_context(|| format!("移除未能启动的新二进制失败: {}", current.display()))?;
    }
    std::fs::rename(backup, current)
        .with_context(|| format!("恢复备份二进制失败: {}", backup.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        GithubRelease, ReleaseAsset, compare_versions, install_guidance, parse_checksum,
        release_target, replace_binary, restore_binary, select_release_assets, unpack_archive,
        update_status, verify_sha256,
    };

    #[test]
    fn compares_release_versions_without_accepting_prereleases() {
        assert!(compare_versions("0.5.0", "v0.6.0").unwrap().is_lt());
        assert!(compare_versions("0.5.0", "v0.5.0").unwrap().is_eq());
        assert!(compare_versions("0.5.0", "v0.6.0-rc.1").is_err());
    }

    #[test]
    fn selects_only_the_current_platform_archive_and_checksum() {
        let assets = vec![
            ReleaseAsset::new("powermap-aarch64-apple-darwin.tar.gz", "archive"),
            ReleaseAsset::new("powermap-aarch64-apple-darwin.sha256", "checksum"),
            ReleaseAsset::new("powermap-x86_64-unknown-linux-gnu.tar.gz", "other"),
        ];
        let selected = select_release_assets(&assets, "aarch64-apple-darwin").unwrap();
        assert_eq!(
            selected.archive.name,
            "powermap-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            selected.checksum.name,
            "powermap-aarch64-apple-darwin.sha256"
        );
    }

    #[test]
    fn parses_the_checksum_for_the_expected_archive_only() {
        let checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  powermap-aarch64-apple-darwin.tar.gz\n";
        assert_eq!(
            parse_checksum(checksum, "powermap-aarch64-apple-darwin.tar.gz").unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(parse_checksum(checksum, "powermap-x86_64-apple-darwin.tar.gz").is_err());
    }

    #[test]
    fn release_metadata_keeps_the_download_urls() {
        let release: GithubRelease = serde_json::from_str(
            r#"{
                "tag_name":"v0.6.0",
                "html_url":"https://github.com/steven-ld/PowerMap/releases/tag/v0.6.0",
                "body":"notes",
                "assets":[{"name":"powermap-aarch64-apple-darwin.tar.gz","browser_download_url":"https://example.test/archive"}]
            }"#,
        )
        .unwrap();
        assert_eq!(
            release.assets[0].browser_download_url,
            "https://example.test/archive"
        );
        assert!(
            compare_versions("0.5.0", &release.tag_name)
                .unwrap()
                .is_lt()
        );
    }

    #[test]
    fn update_status_only_offers_newer_stable_releases() {
        let release: GithubRelease = serde_json::from_str(
            r#"{"tag_name":"v0.6.0","html_url":"https://example.test/v0.6.0","assets":[]}"#,
        )
        .unwrap();
        assert!(update_status("0.5.0", &release).unwrap().update_available);

        let prerelease: GithubRelease = serde_json::from_str(
            r#"{"tag_name":"v0.7.0-rc.1","html_url":"https://example.test/v0.7.0-rc.1","prerelease":true,"assets":[]}"#,
        )
        .unwrap();
        assert!(update_status("0.5.0", &prerelease).is_err());
    }

    #[test]
    fn sha256_verification_rejects_tampered_release_bytes() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_sha256(b"abc", expected).is_ok());
        assert!(verify_sha256(b"abd", expected).is_err());
    }

    #[test]
    fn unpacking_release_extracts_only_the_powermap_binary() {
        use std::io::Write;

        let mut archive = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut archive);
            let bytes = b"new-binary";
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, "powermap", &bytes[..])
                .unwrap();
            let readme = b"PowerMap release notes";
            let mut readme_header = tar::Header::new_gnu();
            readme_header.set_size(readme.len() as u64);
            readme_header.set_mode(0o644);
            readme_header.set_cksum();
            tar.append_data(&mut readme_header, "README.md", &readme[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&archive).unwrap();
        let target = tempfile::tempdir().unwrap();
        let binary = unpack_archive(&gzip.finish().unwrap(), target.path()).unwrap();
        assert_eq!(std::fs::read(binary).unwrap(), b"new-binary");
    }

    #[test]
    fn replacing_binary_keeps_a_backup_that_can_be_restored() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("powermap");
        let staged = dir.path().join("staged-powermap");
        std::fs::write(&current, b"old-binary").unwrap();
        std::fs::write(&staged, b"new-binary").unwrap();

        let backup = replace_binary(&current, &staged).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"new-binary");
        assert_eq!(std::fs::read(&backup).unwrap(), b"old-binary");

        restore_binary(&current, &backup).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"old-binary");
    }

    #[test]
    fn target_name_matches_the_release_asset_convention() {
        assert_eq!(
            release_target("macos", "aarch64").unwrap(),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            release_target("linux", "x86_64").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert!(release_target("windows", "x86_64").is_err());
    }

    #[test]
    fn install_guidance_offers_host_commands_for_docker_and_windows() {
        assert_eq!(
            install_guidance("linux", true, false, false, "v0.6.0").kind,
            "docker"
        );
        assert!(
            install_guidance("linux", true, false, false, "v0.6.0")
                .command
                .unwrap()
                .contains("POWERMAP_TAG=v0.6.0")
        );
        assert_eq!(
            install_guidance("windows", false, false, false, "v0.6.0").kind,
            "windows"
        );
        assert!(
            install_guidance("windows", false, false, false, "v0.6.0")
                .command
                .unwrap()
                .contains("v0.6.0/scripts/install.ps1")
        );
        assert_eq!(
            install_guidance("linux", false, true, false, "v0.6.0").kind,
            "systemd"
        );
        assert_eq!(
            install_guidance("macos", false, false, false, "v0.6.0").kind,
            "in_app"
        );
        assert_eq!(
            install_guidance("macos", false, false, true, "v0.6.0").kind,
            "launchd"
        );
    }
}
