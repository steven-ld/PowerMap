//! 固定配置：A/B 两端各自一份 TOML，首次运行生成、之后自动复用，
//! 这样重启不需要重新配置，映射规则、凭证也持久化。

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

static SAVE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 一条端口映射：本地监听地址 → B 端所在内网里的目标 host:port。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mapping {
    /// 本地监听地址，可填 127.0.0.1:8080，也可填 127.0.0.2:6379 这类 127/8 虚拟 IP
    pub local: String,
    /// 目标主机（B 端内网里能访问到的 IP / 主机名）
    pub host: String,
    /// 目标端口
    pub port: u16,
}

impl Mapping {
    /// 校验映射字段合法性，返回中文错误描述。
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.local.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!("本地监听地址 {} 不是合法的 host:port", self.local));
        }
        let host = self.host.trim();
        if host.is_empty() {
            return Err("目标主机不能为空".into());
        }
        if host.len() > 255 {
            return Err("目标主机名过长".into());
        }
        if host.chars().any(|c| c.is_ascii_whitespace()) {
            return Err("目标主机不能含空白字符".into());
        }
        if self.port == 0 {
            return Err("目标端口不能为 0".into());
        }
        Ok(())
    }
}

/// 用户端 A 的配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AConfig {
    /// B 端的 EndpointId（PublicKey 字符串）
    #[serde(default)]
    pub node_id: String,
    /// 访问令牌
    #[serde(default)]
    pub token: String,
    /// Web 管理页监听地址
    #[serde(default = "default_web_bind")]
    pub web_bind: String,
    /// Web 管理页访问令牌；留空表示不鉴权（仅本机回环时可留空，绑定 0.0.0.0 远程管理时务必设置）
    #[serde(default)]
    pub web_token: String,
    /// Web 管理页 TLS 证书路径（PEM）；与 web_tls_key 同时非空则启用 HTTPS
    #[serde(default)]
    pub web_tls_cert: String,
    /// Web 管理页 TLS 私钥路径（PEM）
    #[serde(default)]
    pub web_tls_key: String,
    /// 最大映射条数上限（防止无限添加耗尽本地端口/资源）
    #[serde(default = "default_max_mappings")]
    pub max_mappings: usize,
    /// 单条映射的最大并发连接数（0 = 不限）
    #[serde(default = "default_max_conns_per_mapping")]
    pub max_conns_per_mapping: usize,
    /// 映射规则列表（持久化，重启自动恢复）
    #[serde(default)]
    pub mappings: Vec<Mapping>,
}

impl Default for AConfig {
    fn default() -> Self {
        AConfig {
            node_id: String::new(),
            token: String::new(),
            web_bind: default_web_bind(),
            web_token: String::new(),
            web_tls_cert: String::new(),
            web_tls_key: String::new(),
            max_mappings: default_max_mappings(),
            max_conns_per_mapping: default_max_conns_per_mapping(),
            mappings: Vec::new(),
        }
    }
}

impl AConfig {
    /// 检查启动前必须明确处理的配置。空凭证仍可用于首次启动，由 Web 管理页完成接入。
    pub fn validate(&self) -> std::result::Result<(), String> {
        let web_bind: SocketAddr = self
            .web_bind
            .parse()
            .map_err(|_| format!("web_bind 不是合法地址: {}", self.web_bind))?;
        if !web_bind.ip().is_loopback() && self.web_token.trim().is_empty() {
            return Err(format!(
                "Web 监听 {} 非回环，必须设置 web_token 以保护管理接口",
                self.web_bind
            ));
        }
        if self.web_tls_cert.is_empty() != self.web_tls_key.is_empty() {
            return Err("web_tls_cert 与 web_tls_key 必须同时设置或同时留空".into());
        }
        if self.node_id.trim().is_empty() != self.token.trim().is_empty() {
            return Err("node_id 与 token 必须同时设置；也可同时留空并在管理页完成接入".into());
        }

        let mut locals = HashSet::new();
        for mapping in &self.mappings {
            mapping.validate()?;
            if !locals.insert(&mapping.local) {
                return Err(format!("本地监听地址 {} 重复", mapping.local));
            }
        }
        Ok(())
    }
}

fn default_web_bind() -> String {
    "127.0.0.1:8088".to_string()
}

fn default_max_mappings() -> usize {
    256
}

fn default_max_conns_per_mapping() -> usize {
    512
}

/// 一个客户端凭证（多租户）：各自独立 token + 独立目标白名单，可单独吊销/轮换。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCred {
    /// 客户标识（用于审计日志与指标标签，非机密）
    pub id: String,
    /// 该客户的访问令牌
    pub token: String,
    /// 允许拨号的目标网段（CIDR）；留空=允许全部
    #[serde(default)]
    pub allow_networks: Vec<String>,
    /// 允许拨号的目标端口；留空=允许全部
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    /// 该客户的最大并发隧道数（0 = 不限）
    #[serde(default)]
    pub max_streams: usize,
    /// 是否已吊销（保留在配置中留痕，但拒绝接入）
    #[serde(default)]
    pub revoked: bool,
}

/// 穿透端 B 的配置。
///
/// 兼容两种模式：
/// - 单租户（旧）：顶层 `token` + `allow_networks` + `allow_ports`；
/// - 多租户（新）：`[[clients]]` 列表，每个客户独立 token 与策略。
///
/// 两者可并存：加载时会把顶层单 token 归一化为一个 id 为 "default" 的客户。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BConfig {
    /// 节点身份文件路径（持久化 node id，重启保持稳定）
    #[serde(default = "default_identity")]
    pub identity: String,
    /// 单租户访问令牌；留空且无 clients 时首次运行随机生成并回填
    #[serde(default)]
    pub token: String,
    /// 单租户模式下允许拨号的目标网段（CIDR）；留空表示允许全部
    #[serde(default)]
    pub allow_networks: Vec<String>,
    /// 单租户模式下允许拨号的目标端口；留空表示允许全部
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    /// 多租户客户端列表
    #[serde(default)]
    pub clients: Vec<ClientCred>,
    /// 单连接上的最大并发隧道数（全局上限，0 = 不限）
    #[serde(default = "default_max_streams_per_conn")]
    pub max_streams_per_conn: usize,
    /// 内网拨号超时（秒）
    #[serde(default = "default_dial_timeout_secs")]
    pub dial_timeout_secs: u64,
    /// 审计日志文件路径；留空则只输出到 tracing
    #[serde(default)]
    pub audit_log: String,
}

impl Default for BConfig {
    fn default() -> Self {
        BConfig {
            identity: default_identity(),
            token: String::new(),
            allow_networks: Vec::new(),
            allow_ports: Vec::new(),
            clients: Vec::new(),
            max_streams_per_conn: default_max_streams_per_conn(),
            dial_timeout_secs: default_dial_timeout_secs(),
            audit_log: String::new(),
        }
    }
}

impl BConfig {
    /// 归一化为客户端列表：把顶层单 token 折叠成一个 id="default" 的客户，
    /// 与显式配置的 clients 合并。返回的每个客户 token 都非空。
    pub fn effective_clients(&self) -> Vec<ClientCred> {
        let mut out: Vec<ClientCred> = Vec::new();
        if !self.token.is_empty() {
            out.push(ClientCred {
                id: "default".to_string(),
                token: self.token.clone(),
                allow_networks: self.allow_networks.clone(),
                allow_ports: self.allow_ports.clone(),
                max_streams: 0,
                revoked: false,
            });
        }
        for c in &self.clients {
            if !c.token.is_empty() {
                out.push(c.clone());
            }
        }
        out
    }

    /// 顶层 token 仍是兼容的单租户配置格式，而非一次性的自动迁移结果。
    pub fn uses_legacy_single_token(&self) -> bool {
        !self.token.is_empty()
    }

    /// 检查 B 端策略是否会被静默忽略或产生歧义。
    ///
    /// 顶层 `token`、`allow_networks` 和 `allow_ports` 是仍受支持的旧单租户格式；
    /// 运行时会继续将其归一化为 id 为 `default` 的客户。
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.identity.trim().is_empty() {
            return Err("identity 不能为空".into());
        }
        if self.dial_timeout_secs == 0 {
            return Err("dial_timeout_secs 必须大于 0".into());
        }

        validate_policy("默认客户", &self.allow_networks, &self.allow_ports)?;
        let mut ids = HashSet::new();
        let mut tokens = HashSet::new();
        if !self.token.is_empty() {
            ids.insert("default".to_string());
            tokens.insert(self.token.as_str());
        }
        for client in &self.clients {
            if client.id.trim().is_empty() {
                return Err("clients 中的 id 不能为空".into());
            }
            if client.token.trim().is_empty() {
                return Err(format!("客户 {} 的 token 不能为空", client.id));
            }
            if !ids.insert(client.id.clone()) {
                return Err(format!("客户 id {} 重复", client.id));
            }
            if !tokens.insert(client.token.as_str()) {
                return Err(format!("客户 {} 使用了重复 token", client.id));
            }
            validate_policy(
                &format!("客户 {}", client.id),
                &client.allow_networks,
                &client.allow_ports,
            )?;
        }
        Ok(())
    }
}

fn validate_policy(
    owner: &str,
    allow_networks: &[String],
    allow_ports: &[u16],
) -> std::result::Result<(), String> {
    for cidr in allow_networks {
        cidr.parse::<IpNet>()
            .map_err(|_| format!("{owner} 的 allow_networks 包含无效 CIDR: {cidr}"))?;
    }
    if allow_ports.contains(&0) {
        return Err(format!("{owner} 的 allow_ports 不能包含 0"));
    }
    Ok(())
}

fn default_identity() -> String {
    "powermap-server.key".to_string()
}

fn default_max_streams_per_conn() -> usize {
    256
}

fn default_dial_timeout_secs() -> u64 {
    10
}

/// 默认配置目录：`<系统配置目录>/powermap/`（macOS: ~/Library/Application Support；Linux: ~/.config）。
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("powermap")
}

/// 某个配置文件的默认完整路径。
pub fn default_path(name: &str) -> PathBuf {
    config_dir().join(name)
}

/// 读取 TOML 配置；文件不存在则返回默认值。
pub fn load_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(T::default()),
        Ok(s) => toml::from_str(&s).with_context(|| format!("解析配置失败: {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("读取配置失败: {}", path.display())),
    }
}

/// 写入 TOML 配置（先写入私有的唯一临时文件再原子重命名，避免半截写入）。
pub fn save<T: Serialize>(path: &Path, cfg: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;
    }
    let s = toml::to_string_pretty(cfg).context("序列化配置失败")?;

    let (tmp, mut file) = create_private_temp_file(path)?;
    let write_result = (|| -> Result<()> {
        file.write_all(s.as_bytes())
            .with_context(|| format!("写入配置失败: {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("同步配置失败: {}", tmp.display()))?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }

    std::fs::rename(&tmp, path).with_context(|| format!("替换配置失败: {}", path.display()))?;
    sync_parent_directory(path)?;
    Ok(())
}

fn create_private_temp_file(path: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..16 {
        let tmp = unique_temp_path(path);
        match open_private_new_file(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("创建临时配置失败: {}", tmp.display()));
            }
        }
    }
    anyhow::bail!("无法创建唯一临时配置文件: {}", path.display())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = SAVE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        ".{file_name}.{}.{}.{counter}.tmp",
        std::process::id(),
        timestamp
    ))
}

#[cfg(unix)]
fn open_private_new_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private_new_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .with_context(|| format!("打开配置目录失败: {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("同步配置目录失败: {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_config_path(name: &str) -> PathBuf {
        let counter = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "powermap-config-test-{}-{counter}",
                std::process::id()
            ))
            .join(name)
    }

    #[test]
    fn save_does_not_touch_a_preexisting_legacy_temp_file() {
        let path = test_config_path("client.toml");
        let legacy_temp = path.with_extension("toml.tmp");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&legacy_temp, "do not overwrite").unwrap();

        save(&path, &AConfig::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(&legacy_temp).unwrap(),
            "do not overwrite"
        );
        assert!(load_or_default::<AConfig>(&path).is_ok());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_config_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = test_config_path("server.toml");
        save(&path, &BConfig::default()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_config_roundtrips_through_toml() {
        let cfg = AConfig {
            node_id: "abc".into(),
            token: "t".into(),
            web_bind: "127.0.0.1:9000".into(),
            web_token: String::new(),
            mappings: vec![Mapping {
                local: "127.0.0.1:80".into(),
                host: "10.0.0.1".into(),
                port: 80,
            }],
            ..Default::default()
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: AConfig = toml::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn a_config_has_sane_defaults() {
        let a: AConfig = toml::from_str("").unwrap();
        assert_eq!(a.web_bind, "127.0.0.1:8088");
        assert_eq!(a.max_mappings, 256);
        assert_eq!(a.max_conns_per_mapping, 512);
        assert!(a.web_tls_cert.is_empty() && a.web_tls_key.is_empty());
    }

    #[test]
    fn single_token_normalizes_to_default_client() {
        let b = BConfig {
            token: "tok".into(),
            allow_networks: vec!["10.0.0.0/8".into()],
            allow_ports: vec![6379],
            ..Default::default()
        };
        let clients = b.effective_clients();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, "default");
        assert_eq!(clients[0].token, "tok");
        assert_eq!(clients[0].allow_ports, vec![6379]);
    }

    #[test]
    fn multi_tenant_and_single_token_coexist() {
        let toml_str = r#"
token = "legacy"
allow_ports = [6379]

[[clients]]
id = "alice"
token = "atok"
allow_networks = ["192.168.1.0/24"]

[[clients]]
id = "bob"
token = "btok"
revoked = true
"#;
        let b: BConfig = toml::from_str(toml_str).unwrap();
        let clients = b.effective_clients();
        // legacy default + alice + bob(即使 revoked 也在列表里，接入时再拒)
        assert_eq!(clients.len(), 3);
        assert_eq!(clients[0].id, "default");
        assert_eq!(clients[1].id, "alice");
        assert!(clients[2].revoked);
        // 空 token 的 client 会被过滤
        let s = toml::to_string(&b).unwrap();
        let back: BConfig = toml::from_str(&s).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn empty_token_client_is_filtered() {
        let b = BConfig {
            token: String::new(),
            clients: vec![ClientCred {
                id: "ghost".into(),
                token: String::new(),
                allow_networks: vec![],
                allow_ports: vec![],
                max_streams: 0,
                revoked: false,
            }],
            ..Default::default()
        };
        assert!(b.effective_clients().is_empty());
    }

    #[test]
    fn empty_b_config_uses_default_identity() {
        let b: BConfig = toml::from_str("").unwrap();
        assert_eq!(b.identity, "powermap-server.key");
        assert!(b.token.is_empty());
    }

    #[test]
    fn b_config_allowlist_roundtrips() {
        let toml_str = r#"
identity = "k.key"
token = "t"
allow_networks = ["10.0.0.0/8"]
allow_ports = [22, 443]
"#;
        let b: BConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(b.allow_networks, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(b.allow_ports, vec![22, 443]);
        let s = toml::to_string(&b).unwrap();
        let back: BConfig = toml::from_str(&s).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn effective_clients_folds_top_level_token_to_default() {
        let b = BConfig {
            token: "top".into(),
            allow_networks: vec!["10.0.0.0/8".into()],
            allow_ports: vec![6379],
            ..Default::default()
        };
        let cs = b.effective_clients();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].id, "default");
        assert_eq!(cs[0].token, "top");
        assert_eq!(cs[0].allow_networks, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(cs[0].allow_ports, vec![6379]);
    }

    #[test]
    fn effective_clients_merges_top_level_and_explicit_clients() {
        let b = BConfig {
            token: "top".into(),
            clients: vec![
                ClientCred {
                    id: "alice".into(),
                    token: "atok".into(),
                    allow_networks: vec!["192.168.0.0/16".into()],
                    allow_ports: vec![],
                    max_streams: 4,
                    revoked: false,
                },
                // token 为空的客户被忽略
                ClientCred {
                    id: "empty".into(),
                    token: "".into(),
                    ..ClientCred {
                        id: String::new(),
                        token: String::new(),
                        allow_networks: vec![],
                        allow_ports: vec![],
                        max_streams: 0,
                        revoked: false,
                    }
                },
            ],
            ..Default::default()
        };
        let cs = b.effective_clients();
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].id, "default");
        assert_eq!(cs[1].id, "alice");
        assert_eq!(cs[1].max_streams, 4);
    }

    #[test]
    fn effective_clients_empty_when_nothing_configured() {
        let b = BConfig::default();
        assert!(b.effective_clients().is_empty());
    }

    #[test]
    fn b_config_multitenant_roundtrips() {
        let toml_str = r#"
identity = "k.key"
max_streams_per_conn = 128
dial_timeout_secs = 5

[[clients]]
id = "alice"
token = "atok"
allow_networks = ["192.168.1.0/24"]
allow_ports = [6379]
max_streams = 8
revoked = false
"#;
        let b: BConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(b.clients.len(), 1);
        assert_eq!(b.clients[0].id, "alice");
        assert_eq!(b.max_streams_per_conn, 128);
        assert_eq!(b.dial_timeout_secs, 5);
        let s = toml::to_string(&b).unwrap();
        let back: BConfig = toml::from_str(&s).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn mapping_validate_rejects_bad_input() {
        assert!(
            Mapping {
                local: "127.0.0.1:8080".into(),
                host: "10.0.0.1".into(),
                port: 80
            }
            .validate()
            .is_ok()
        );
        assert!(
            Mapping {
                local: "not-an-addr".into(),
                host: "10.0.0.1".into(),
                port: 80
            }
            .validate()
            .is_err()
        );
        assert!(
            Mapping {
                local: "127.0.0.1:8080".into(),
                host: "".into(),
                port: 80
            }
            .validate()
            .is_err()
        );
        assert!(
            Mapping {
                local: "127.0.0.1:8080".into(),
                host: "a b".into(),
                port: 80
            }
            .validate()
            .is_err()
        );
        assert!(
            Mapping {
                local: "127.0.0.1:8080".into(),
                host: "10.0.0.1".into(),
                port: 0
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn a_config_rejects_unsafe_or_incomplete_runtime_settings() {
        let cases = [
            AConfig {
                web_bind: "0.0.0.0:8088".into(),
                ..Default::default()
            },
            AConfig {
                web_tls_cert: "cert.pem".into(),
                ..Default::default()
            },
            AConfig {
                node_id: "node".into(),
                ..Default::default()
            },
        ];

        for cfg in cases {
            assert!(cfg.validate().is_err());
        }
    }

    #[test]
    fn legacy_single_token_server_config_stays_valid() {
        let cfg: BConfig = toml::from_str(
            r#"
token = "legacy-token"
allow_networks = ["10.0.0.0/8"]
allow_ports = [443]
"#,
        )
        .unwrap();

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn b_config_rejects_ambiguous_or_invalid_client_policies() {
        let invalid_cidr: BConfig = toml::from_str(
            r#"
[[clients]]
id = "alice"
token = "token-a"
allow_networks = ["not-a-cidr"]
"#,
        )
        .unwrap();
        assert!(invalid_cidr.validate().is_err());

        let duplicate_token: BConfig = toml::from_str(
            r#"
[[clients]]
id = "alice"
token = "shared-token"

[[clients]]
id = "bob"
token = "shared-token"
"#,
        )
        .unwrap();
        assert!(duplicate_token.validate().is_err());
    }
}
