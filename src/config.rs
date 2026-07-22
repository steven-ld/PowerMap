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

/// 一条映射承载的传输/代理模式。旧配置省略此字段时按 tcp 处理，保持兼容。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MappingMode {
    /// 裸 TCP 透传（默认，原有行为）。
    #[default]
    Tcp,
    /// UDP 透传：本地绑定 UDP socket，数据报经隧道到达 B 端后由 B 拨 UDP 目标。
    Udp,
    /// HTTP 反向代理网关：单个本地端口按 Host 头路由到多个内网 HTTP 后端。
    Http,
}

impl MappingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MappingMode::Tcp => "tcp",
            MappingMode::Udp => "udp",
            MappingMode::Http => "http",
        }
    }
}

/// HTTP 网关的一条路由：按请求的 Host 头（不含端口）匹配到具体内网后端。
/// `host_match` 为空表示兜底路由，匹配任意未命中的 Host。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpRoute {
    /// 要匹配的 Host 头（大小写不敏感，比较时忽略端口），例如 "grafana.local"。
    #[serde(default)]
    pub host_match: String,
    /// 命中后拨号的内网目标主机。
    pub target_host: String,
    /// 命中后拨号的内网目标端口。
    pub target_port: u16,
}

impl HttpRoute {
    pub fn validate(&self) -> std::result::Result<(), String> {
        let m = self.host_match.trim();
        if m.len() > 255 || m.chars().any(|c| c.is_ascii_whitespace()) {
            return Err("HTTP 路由的 host_match 不能含空白且不超过 255 字符".into());
        }
        let host = self.target_host.trim();
        if host.is_empty() || host.len() > 255 || host.chars().any(|c| c.is_ascii_whitespace()) {
            return Err("HTTP 路由的 target_host 必须是有效 IP 或主机名".into());
        }
        if self.target_port == 0 {
            return Err("HTTP 路由的 target_port 不能为 0".into());
        }
        Ok(())
    }
}

/// 一条端口映射：本地监听地址 → B 端所在内网里的目标 host:port。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mapping {
    /// 本地监听地址，可填 127.0.0.1:8080，也可填 127.0.0.2:6379 这类 127/8 虚拟 IP
    pub local: String,
    /// 目标主机（B 端内网里能访问到的 IP / 主机名）。HTTP 网关模式下作为兜底后端。
    pub host: String,
    /// 目标端口。HTTP 网关模式下作为兜底后端端口。
    pub port: u16,
    /// 是否启用；停用后释放本地端口、不再接受连接，但保留在配置里可随时再启用。
    /// 旧配置没有此字段时默认启用，保持向后兼容。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 可选的可读名称，例如 "Redis 主库"。仅用于管理页展示与搜索，不影响连接行为。
    /// 旧配置没有此字段时为空，保持向后兼容。
    #[serde(default)]
    pub name: String,
    /// 传输/代理模式（tcp / udp / http）。旧配置省略时为 tcp。
    #[serde(default)]
    pub mode: MappingMode,
    /// HTTP 网关模式下的按 Host 路由表；其他模式忽略。
    #[serde(default)]
    pub routes: Vec<HttpRoute>,
}

fn default_enabled() -> bool {
    true
}

fn default_https_port() -> u16 {
    443
}

/// A domain name that should be exposed through the remote node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainMapping {
    /// Lowercase DNS domain name, for example "ai-router.dl-aiot.com".
    pub domain: String,
    /// Remote HTTPS port. Defaults to 443 for legacy-compatible concise config.
    #[serde(default = "default_https_port")]
    pub remote_port: u16,
    /// Whether this mapping is active. Defaults to enabled when omitted.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl DomainMapping {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            remote_port: default_https_port(),
            enabled: default_enabled(),
        }
    }

    pub fn validate(&self) -> std::result::Result<(), String> {
        let domain = self.domain.as_str();
        if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
            return Err("domain 必须是长度不超过 253 的完整 DNS 名称".into());
        }
        if domain.parse::<std::net::IpAddr>().is_ok() {
            return Err("domain 不能是 IP 地址".into());
        }
        for label in domain.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err("domain 必须由小写 DNS 标签组成".into());
            }
        }
        if self.remote_port == 0 {
            return Err("domain 的 remote_port 不能为 0".into());
        }
        Ok(())
    }
}

/// B 端明确允许在 client 管理页中推荐的目标服务。
///
/// 这不是一条额外的访问授权：实际拨号仍由 allow_networks / allow_ports
/// 决定。它只避免 client 为了找服务而扫描整个内网。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedTarget {
    /// B 端内网可访问的 IP 或主机名。
    pub host: String,
    /// 服务端口。
    pub port: u16,
    /// 控制台中展示的可读名称，例如 "Redis 主库"。
    #[serde(default)]
    pub label: String,
}

impl PublishedTarget {
    pub fn validate(&self) -> std::result::Result<(), String> {
        let host = self.host.trim();
        if host.is_empty() || host.len() > 255 || host.chars().any(|c| c.is_ascii_whitespace()) {
            return Err("published_targets 的 host 必须是有效的 IP 或主机名".into());
        }
        if self.port == 0 {
            return Err("published_targets 的 port 不能为 0".into());
        }
        if self.label.len() > 80 {
            return Err("published_targets 的 label 不能超过 80 个字符".into());
        }
        Ok(())
    }
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
        if self.name.chars().count() > 60 {
            return Err("映射名称不能超过 60 个字符".into());
        }
        // HTTP 网关模式：校验每条路由，且兜底 Host（空 host_match）最多一条。
        if self.mode == MappingMode::Http {
            if self.routes.len() > 32 {
                return Err("HTTP 网关的路由最多 32 条".into());
            }
            let mut catch_all = 0;
            let mut seen = HashSet::new();
            for route in &self.routes {
                route.validate()?;
                let key = route.host_match.trim().to_ascii_lowercase();
                if key.is_empty() {
                    catch_all += 1;
                } else if !seen.insert(key) {
                    return Err(format!("HTTP 路由的 host_match {} 重复", route.host_match));
                }
            }
            if catch_all > 1 {
                return Err("HTTP 网关最多只能有一条兜底路由（空 host_match）".into());
            }
        } else if !self.routes.is_empty() {
            return Err("仅 HTTP 网关模式可配置 routes".into());
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
    /// 域名映射规则（持久化，重启自动恢复）。
    #[serde(default)]
    pub domain_mappings: Vec<DomainMapping>,
    /// 从 B 端凭证带入的推荐目标；只用于管理页自动填写，不改变访问授权。
    #[serde(default)]
    pub published_targets: Vec<PublishedTarget>,
    /// 反向映射总开关：是否接受 B 端发起的反向隧道（把 A 侧服务暴露给内网）。
    /// 默认关闭；即使 B 端配置了反向监听，A 端不开此开关也一律拒绝，避免被动暴露本机服务。
    #[serde(default)]
    pub reverse_enabled: bool,
    /// 反向映射允许 A 端拨号的目标网段（CIDR）。
    /// 与正向白名单相反：留空表示**全部拒绝**（deny-all），必须显式列出才放行。
    #[serde(default)]
    pub reverse_allow_networks: Vec<String>,
    /// 反向映射允许 A 端拨号的目标端口。留空表示**全部拒绝**（deny-all）。
    #[serde(default)]
    pub reverse_allow_ports: Vec<u16>,
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
            domain_mappings: Vec::new(),
            published_targets: Vec::new(),
            reverse_enabled: false,
            reverse_allow_networks: Vec::new(),
            reverse_allow_ports: Vec::new(),
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
        for mapping in &self.domain_mappings {
            mapping.validate()?;
        }
        for target in &self.published_targets {
            target.validate()?;
        }
        // 反向映射的允许网段必须是合法 CIDR；deny-all 语义下留空是合法的（表示全拒绝）。
        // 只校验格式，空集=拒绝的语义留给运行期 ReversePolicy。
        validate_allowlist(
            "reverse_allow_networks",
            "reverse_allow_ports",
            &self.reverse_allow_networks,
            &self.reverse_allow_ports,
        )?;
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

/// 一条反向监听：B 端在内网某地址监听，把连接经隧道交给 A 端拨自己一侧的目标。
/// 与正向相反——发起端是 B，拨号端是 A，因此受 A 端的 reverse_allow_* 策略约束。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReverseListen {
    /// B 端内网监听地址（内网设备可访问），例如 0.0.0.0:9000 或 192.168.1.5:9000。
    pub listen: String,
    /// A 端一侧要拨号的目标主机（A 端本机或其家庭网络里的地址）。
    pub target_host: String,
    /// A 端一侧要拨号的目标端口。
    pub target_port: u16,
    /// 可选可读名称，仅用于日志与展示。
    #[serde(default)]
    pub name: String,
}

impl ReverseListen {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.listen.parse::<SocketAddr>().is_err() {
            return Err(format!("反向监听地址 {} 不是合法的 host:port", self.listen));
        }
        let host = self.target_host.trim();
        if host.is_empty() || host.len() > 255 || host.chars().any(|c| c.is_ascii_whitespace()) {
            return Err("反向监听的 target_host 必须是有效 IP 或主机名".into());
        }
        if self.target_port == 0 {
            return Err("反向监听的 target_port 不能为 0".into());
        }
        if self.name.chars().count() > 60 {
            return Err("反向监听名称不能超过 60 个字符".into());
        }
        Ok(())
    }
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
    /// 仅对该客户公开的推荐目标，client 会在创建映射时实际拨号验证后展示。
    #[serde(default)]
    pub published_targets: Vec<PublishedTarget>,
    /// 该客户的反向监听：B 端在内网监听、交给 A 端拨其一侧目标。
    /// 实际是否放行由 A 端的 reverse_enabled / reverse_allow_* 决定（deny-all）。
    #[serde(default)]
    pub reverse: Vec<ReverseListen>,
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
    /// 单租户模式下向 client 推荐的目标服务；需同时受白名单允许。
    #[serde(default)]
    pub published_targets: Vec<PublishedTarget>,
    /// 单租户模式下的反向监听（折叠进 default 客户）。
    #[serde(default)]
    pub reverse: Vec<ReverseListen>,
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
            published_targets: Vec::new(),
            reverse: Vec::new(),
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
                published_targets: self.published_targets.clone(),
                reverse: self.reverse.clone(),
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
        validate_published_targets(
            "默认客户",
            &self.published_targets,
            &self.allow_networks,
            &self.allow_ports,
        )?;
        // 反向监听地址在整个 server 内唯一（多个客户不能抢同一个内网监听端口）。
        let mut reverse_listens = HashSet::new();
        validate_reverse("默认客户", &self.reverse, &mut reverse_listens)?;
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
            validate_published_targets(
                &format!("客户 {}", client.id),
                &client.published_targets,
                &client.allow_networks,
                &client.allow_ports,
            )?;
            validate_reverse(
                &format!("客户 {}", client.id),
                &client.reverse,
                &mut reverse_listens,
            )?;
        }
        Ok(())
    }
}

/// 统一进程配置：一个节点可只暴露服务、只接入服务，或同时具备两种能力。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub expose: Option<BConfig>,
    #[serde(default)]
    pub access: Option<AConfig>,
}

/// 首次设置时用户选择的使用场景。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// 在本机创建映射，访问另一端暴露的内网服务。
    Access,
    /// 把当前网络中的服务暴露给持有凭证的接入方。
    Expose,
    /// 同时接入另一网络并暴露当前网络。
    Both,
}

impl Config {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.expose.is_none() && self.access.is_none() {
            return Err("配置至少需要 expose 或 access 角色".into());
        }
        if let Some(expose) = &self.expose {
            expose.validate()?;
        }
        if let Some(access) = &self.access {
            access.validate()?;
        }
        Ok(())
    }

    fn default_node() -> Self {
        Self::for_scenario(Scenario::Both)
    }

    /// 用安全默认值初始化用户选择的场景；反向访问仍默认禁用。
    pub fn for_scenario(scenario: Scenario) -> Self {
        match scenario {
            Scenario::Access => Self {
                expose: None,
                access: Some(AConfig::default()),
            },
            Scenario::Expose => Self {
                expose: Some(BConfig::default()),
                access: None,
            },
            Scenario::Both => Self {
                expose: Some(BConfig::default()),
                access: Some(AConfig::default()),
            },
        }
    }
}

/// 指定路径是旧配置时，调用方可明确其应迁移到的角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyRole {
    Expose,
    Access,
}

/// 统一配置加载的结果。迁移旧配置时 `path` 指向新写入的 `powermap.toml`。
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub path: PathBuf,
}

/// 加载统一配置，或在默认位置自动合并旧 server/client 配置。
///
/// 迁移的提交顺序是：解析全部旧文件 -> 校验组合配置 -> 原子写入新文件 -> 删除旧文件。
/// 因而任何解析、校验或写入失败都会保留原文件。
pub fn load_config(path: &Path, legacy_role: Option<LegacyRole>) -> Result<LoadedConfig> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        if raw.trim().is_empty() {
            let config = Config::default_node();
            return Ok(LoadedConfig {
                config,
                path: path.to_path_buf(),
            });
        }
        if let Ok(config) = toml::from_str::<Config>(&raw) {
            config.validate().map_err(anyhow::Error::msg)?;
            return Ok(LoadedConfig {
                config,
                path: path.to_path_buf(),
            });
        }

        let role = legacy_role
            .or_else(|| infer_legacy_role(path))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} 不是统一配置；请使用 powermap expose/access --config 指定旧配置角色",
                    path.display()
                )
            })?;
        return migrate_legacy_files(
            path.with_file_name("powermap.toml"),
            &[(path.to_path_buf(), role)],
        );
    }

    let server = path.with_file_name("powermap-server.toml");
    let client = path.with_file_name("powermap-client.toml");
    let mut legacy = Vec::new();
    if server.exists() {
        legacy.push((server, LegacyRole::Expose));
    }
    if client.exists() {
        legacy.push((client, LegacyRole::Access));
    }
    if legacy.is_empty() {
        return Ok(LoadedConfig {
            config: Config::default_node(),
            path: path.to_path_buf(),
        });
    }
    migrate_legacy_files(path.to_path_buf(), &legacy)
}

/// 将接入侧运行时修改写回统一配置，同时保留 expose 段。
pub fn save_access(path: &Path, access: &AConfig) -> Result<()> {
    let mut config = load_config(path, None)?.config;
    config.access = Some(access.clone());
    config.validate().map_err(anyhow::Error::msg)?;
    save(path, &config)
}

fn infer_legacy_role(path: &Path) -> Option<LegacyRole> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.contains("server") {
        Some(LegacyRole::Expose)
    } else if name.contains("client") {
        Some(LegacyRole::Access)
    } else {
        None
    }
}

fn migrate_legacy_files(
    new_path: PathBuf,
    legacy: &[(PathBuf, LegacyRole)],
) -> Result<LoadedConfig> {
    let mut config = Config {
        expose: None,
        access: None,
    };
    for (path, role) in legacy {
        match role {
            LegacyRole::Expose => {
                config.expose = Some(load_or_default::<BConfig>(path)?);
            }
            LegacyRole::Access => {
                config.access = Some(load_or_default::<AConfig>(path)?);
            }
        }
    }
    config.validate().map_err(anyhow::Error::msg)?;
    save(&new_path, &config)?;
    for (path, _) in legacy {
        std::fs::remove_file(path)
            .with_context(|| format!("删除已迁移的旧配置失败: {}", path.display()))?;
    }
    Ok(LoadedConfig {
        config,
        path: new_path,
    })
}

/// 校验一组反向监听：每条本身合法，且监听地址在整个 server 内不重复。
fn validate_reverse(
    owner: &str,
    reverse: &[ReverseListen],
    seen_listens: &mut HashSet<String>,
) -> std::result::Result<(), String> {
    if reverse.len() > 32 {
        return Err(format!("{owner} 的 reverse 最多可配置 32 条"));
    }
    for r in reverse {
        r.validate()?;
        if !seen_listens.insert(r.listen.clone()) {
            return Err(format!("反向监听地址 {} 重复", r.listen));
        }
    }
    Ok(())
}

/// 校验一组「网段 CIDR + 端口」白名单：CIDR 必须可解析、端口不得为 0。
///
/// 这是正向（`allow_*`）与反向（`reverse_allow_*`）共用的底层校验；两者只是错误
/// 文案里的字段名不同，因此把网段/端口的标签作为参数传入，保持各自原有的报错措辞。
/// **注意**：本函数只校验「格式合法性」，不涉及空集语义（空=放行还是空=拒绝由运行期
/// 的 `TargetPolicy` / `ReversePolicy` 决定），因此正反向都能安全共用。
pub fn validate_allowlist(
    net_label: &str,
    port_label: &str,
    allow_networks: &[String],
    allow_ports: &[u16],
) -> std::result::Result<(), String> {
    for cidr in allow_networks {
        cidr.parse::<IpNet>()
            .map_err(|_| format!("{net_label} 包含无效 CIDR: {cidr}"))?;
    }
    if allow_ports.contains(&0) {
        return Err(format!("{port_label} 不能包含 0"));
    }
    Ok(())
}

/// 正向目标白名单校验：沿用 `{owner} 的 allow_networks / allow_ports` 的报错措辞。
fn validate_policy(
    owner: &str,
    allow_networks: &[String],
    allow_ports: &[u16],
) -> std::result::Result<(), String> {
    validate_allowlist(
        &format!("{owner} 的 allow_networks"),
        &format!("{owner} 的 allow_ports"),
        allow_networks,
        allow_ports,
    )
}

fn validate_published_targets(
    owner: &str,
    targets: &[PublishedTarget],
    allow_networks: &[String],
    allow_ports: &[u16],
) -> std::result::Result<(), String> {
    if targets.len() > 12 {
        return Err(format!("{owner} 的 published_targets 最多可配置 12 项"));
    }
    let policy = crate::tunnel::TargetPolicy::from_config(allow_networks, allow_ports);
    let mut seen = HashSet::new();
    for target in targets {
        target.validate()?;
        let key = (target.host.trim().to_ascii_lowercase(), target.port);
        if !seen.insert(key) {
            return Err(format!("{owner} 的 published_targets 包含重复目标"));
        }
        if !policy.port_allowed(target.port) {
            return Err(format!(
                "{owner} 的 published_targets 端口 {} 不在 allow_ports 中",
                target.port
            ));
        }
    }
    Ok(())
}

fn default_identity() -> String {
    "powermap.key".to_string()
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
                enabled: true,
                name: String::new(),
                mode: MappingMode::Tcp,
                routes: Vec::new(),
            }],
            domain_mappings: vec![DomainMapping::new("ai-router.dl-aiot.com")],
            ..Default::default()
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: AConfig = toml::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn domain_mapping_roundtrips_and_defaults_to_https() {
        let mapping = DomainMapping::new("ai-router.dl-aiot.com");
        assert_eq!(mapping.remote_port, 443);
        assert!(mapping.validate().is_ok());

        let serialized = toml::to_string(&mapping).unwrap();
        let roundtripped: DomainMapping = toml::from_str(&serialized).unwrap();
        assert_eq!(mapping, roundtripped);

        let defaults: DomainMapping = toml::from_str("domain = \"ai-router.dl-aiot.com\"").unwrap();
        assert_eq!(defaults, mapping);
    }

    #[test]
    fn domain_mapping_rejects_wildcards_ips_and_invalid_labels() {
        for domain in ["*.example.com", "127.0.0.1", "-bad.example", "bad..example"] {
            assert!(DomainMapping::new(domain).validate().is_err());
        }
    }

    #[test]
    fn a_config_has_sane_defaults() {
        let a: AConfig = toml::from_str("").unwrap();
        assert_eq!(a.web_bind, "127.0.0.1:8088");
        assert_eq!(a.max_mappings, 256);
        assert_eq!(a.max_conns_per_mapping, 512);
        assert!(a.web_tls_cert.is_empty() && a.web_tls_key.is_empty());
        assert!(a.domain_mappings.is_empty());
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
                published_targets: vec![],
                reverse: vec![],
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
        assert_eq!(b.identity, "powermap.key");
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
    fn published_targets_must_stay_inside_the_port_allowlist() {
        let mut b = BConfig {
            token: "top".into(),
            allow_ports: vec![6379],
            published_targets: vec![PublishedTarget {
                host: "192.168.1.101".into(),
                port: 5432,
                label: "PostgreSQL".into(),
            }],
            ..Default::default()
        };
        assert!(b.validate().is_err());
        b.published_targets[0].port = 6379;
        assert!(b.validate().is_ok());
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
                    published_targets: vec![],
                    reverse: vec![],
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
                        published_targets: vec![],
                        reverse: vec![],
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
        let m = |local: &str, host: &str, port: u16| Mapping {
            local: local.into(),
            host: host.into(),
            port,
            enabled: true,
            name: String::new(),
            mode: MappingMode::default(),
            routes: Vec::new(),
        };
        assert!(m("127.0.0.1:8080", "10.0.0.1", 80).validate().is_ok());
        assert!(m("not-an-addr", "10.0.0.1", 80).validate().is_err());
        assert!(m("127.0.0.1:8080", "", 80).validate().is_err());
        assert!(m("127.0.0.1:8080", "a b", 80).validate().is_err());
        assert!(m("127.0.0.1:8080", "10.0.0.1", 0).validate().is_err());
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

    #[test]
    fn unified_config_migrates_and_combines_legacy_roles() {
        let unified = test_config_path("powermap.toml");
        let dir = unified.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let server = dir.join("powermap-server.toml");
        let client = dir.join("powermap-client.toml");
        std::fs::write(&server, "token = \"server-token\"\n").unwrap();
        std::fs::write(&client, "node_id = \"node\"\ntoken = \"client-token\"\n").unwrap();

        let loaded = load_config(&unified, None).unwrap();

        assert_eq!(loaded.path, unified);
        assert_eq!(loaded.config.expose.unwrap().token, "server-token");
        assert_eq!(loaded.config.access.unwrap().token, "client-token");
        assert!(loaded.path.exists());
        assert!(!server.exists());
        assert!(!client.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unified_config_keeps_legacy_files_when_migration_fails() {
        let unified = test_config_path("powermap.toml");
        let dir = unified.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let server = dir.join("powermap-server.toml");
        std::fs::write(&server, "allow_ports = [0]\n").unwrap();

        assert!(load_config(&unified, None).is_err());

        assert!(server.exists());
        assert!(!unified.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scenario_configures_only_the_requested_roles() {
        let access = Config::for_scenario(Scenario::Access);
        assert!(access.access.is_some());
        assert!(access.expose.is_none());
        assert!(!access.access.unwrap().reverse_enabled);

        let expose = Config::for_scenario(Scenario::Expose);
        assert!(expose.expose.is_some());
        assert!(expose.access.is_none());

        let both = Config::for_scenario(Scenario::Both);
        assert!(both.expose.is_some());
        assert!(both.access.is_some());
    }

    #[test]
    fn missing_unified_config_starts_a_dual_capability_node() {
        let path = test_config_path("powermap.toml");
        let loaded = load_config(&path, None).unwrap();

        assert!(loaded.config.expose.is_some());
        assert!(loaded.config.access.is_some());
    }
}
