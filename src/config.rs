//! 固定配置：A/B 两端各自一份 TOML，首次运行生成、之后自动复用，
//! 这样重启不需要重新配置，映射规则、凭证也持久化。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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

/// 写入 TOML 配置（先写临时文件再原子重命名，避免半截写入）。
pub fn save<T: Serialize>(path: &Path, cfg: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let s = toml::to_string_pretty(cfg).context("序列化配置失败")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, s).with_context(|| format!("写入配置失败: {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("替换配置失败: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
