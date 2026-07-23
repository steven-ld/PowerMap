//! 用户端 A —— 装在家里（或任意想访问内网服务的）电脑上。
//!
//! 首次用 `--credential` 接入一次后，凭证与映射规则都写入配置文件，之后直接
//! 启动即可，无需重复配置；映射规则重启自动恢复。
//!
//! Web 管理页（默认 http://127.0.0.1:8088）支持增删映射。每条映射在本地起一个
//! TCP 监听；每来一个连接，就复用同一条到 B 的 iroh 连接开一条 QUIC 流，握手
//! 带上"目标主机:端口"与令牌，B 在内网拨号后双向透传（支持半关闭）。
//! 后台看门狗保持到 B 的热连接并在断线时主动重连。
//!
//! 可运营性：
//! - `/metrics` 暴露 Prometheus 指标；
//! - 每条隧道注册一个 CancellationToken，删除映射或进程优雅退出时主动 drain 在途连接；
//! - 可选 TLS（web_tls_cert/web_tls_key），远程管理时保护管理流量；
//! - 映射条数与单映射并发连接数有上限，防止无限增长耗尽资源。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post, put};
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;
use crate::{
    config,
    domain_hosts::{HostsError, HostsStore},
    proto, tunnel, update,
};

/// 运行期可变的接入凭证：连接目标（node_id → PublicKey）与访问令牌。
/// 网页配置凭证后原地更新，隧道随即用新凭证连接，无需重启进程。
/// `target` 为 None 表示尚未配置凭证（client 可无凭证启动）。
#[derive(Clone, Default)]
struct Creds {
    node_id: String,
    token: String,
    target: Option<PublicKey>,
    published_targets: Vec<config::PublishedTarget>,
}

/// 到 B 的共享连接池：所有映射的隧道都复用同一条 iroh 连接（QUIC 多流），
/// 连接断开时懒重连。连接目标来自可变的 `Creds`，网页改凭证即时生效。
#[derive(Clone)]
struct Link {
    endpoint: Endpoint,
    creds: Arc<RwLock<Creds>>,
    conn: Arc<Mutex<Option<Connection>>>,
    /// 当前连接建立时刻（unix 毫秒，0 = 未连接）。每次成功新建连接时刷新，
    /// invalidate 时清零，供管理页展示"已连接时长"。
    connected_since: Arc<AtomicU64>,
}

impl Link {
    /// 当前接入令牌（每次建隧道时读取，凭证轮换后新连接立即生效）。
    async fn token(&self) -> String {
        self.creds.read().await.token.clone()
    }

    /// 是否已配置凭证（有合法的连接目标）。
    async fn configured(&self) -> bool {
        self.creds.read().await.target.is_some()
    }

    async fn get(&self) -> Result<Connection> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref()
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        let target = self
            .creds
            .read()
            .await
            .target
            .context("尚未配置凭证：请在 Web 管理页粘贴 server 端的凭证")?;
        let c = self
            .endpoint
            .connect(target, proto::ALPN)
            .await
            .context("连接 B 失败")?;
        *g = Some(c.clone());
        self.connected_since
            .store(now_unix_millis(), Ordering::Relaxed);
        tracing::info!("已（重）连到 B");
        Ok(c)
    }

    async fn invalidate(&self) {
        *self.conn.lock().await = None;
        self.connected_since.store(0, Ordering::Relaxed);
    }

    /// 切换连接目标：更新凭证并断开当前连接，下次 get() 用新凭证重连。
    async fn set_creds(
        &self,
        node_id: String,
        token: String,
        target: PublicKey,
        published_targets: Vec<config::PublishedTarget>,
    ) {
        {
            let mut c = self.creds.write().await;
            c.node_id = node_id;
            c.token = token;
            c.target = Some(target);
            c.published_targets = published_targets;
        }
        self.invalidate().await;
    }

    /// 实时存活判断：检查当前缓存的连接是否仍未被关闭。
    async fn is_alive(&self) -> bool {
        match self.conn.lock().await.as_ref() {
            Some(c) => c.close_reason().is_none(),
            None => false,
        }
    }

    /// 返回当前活跃连接可确认的远端直连 IP。中继地址不属于节点地址，故不在此返回。
    async fn connected_ips(&self) -> Vec<String> {
        let target = match self.creds.read().await.target {
            Some(target) => target,
            None => return Vec::new(),
        };
        let conn = {
            let guard = self.conn.lock().await;
            match guard.as_ref() {
                Some(conn) if conn.close_reason().is_none() => conn.clone(),
                _ => return Vec::new(),
            }
        };

        let mut ips = BTreeSet::new();
        for path in conn.paths().iter() {
            if !path.is_selected() {
                continue;
            }
            if let iroh::TransportAddr::Ip(addr) = path.remote_addr() {
                ips.insert(addr.ip().to_string());
            }
        }
        if let Some(info) = self.endpoint.remote_info(target).await {
            for addr in info.addrs() {
                if !matches!(addr.usage(), iroh::endpoint::TransportAddrUsage::Active) {
                    continue;
                }
                if let iroh::TransportAddr::Ip(socket) = addr.addr() {
                    ips.insert(socket.ip().to_string());
                }
            }
        }
        ips.into_iter().collect()
    }

    /// 当前到 B 的穿透质量快照：路径（direct / relay / unknown）、往返延迟、中继主机。
    /// 优先读活跃连接的“已选路径”，直接拿到该路径的 RTT 与地址类型；
    /// 连接尚无路径快照时回退到 remote_info 判断路径类型。未连接或无凭证时返回 None。
    async fn transport_path(&self) -> Option<PathInfo> {
        let target = self.creds.read().await.target?;
        let conn = {
            let guard = self.conn.lock().await;
            match guard.as_ref() {
                Some(c) if c.close_reason().is_none() => c.clone(),
                _ => return None,
            }
        };

        // 已选路径能同时给出 RTT 与地址类型，是最准确的“当前正在走”的路径。
        // Path 借用 Connection，不能跨 await，因此在此同步提取出所有拥有型数据。
        let selected = {
            let paths = conn.paths();
            let path = paths.into_iter().find(|p| p.is_selected());
            path.map(|p| {
                let rtt_ms = (p.rtt().as_secs_f64() * 1000.0).round() as u64;
                let relay = match p.remote_addr() {
                    iroh::TransportAddr::Relay(url) => url.host_str().map(|h| h.to_string()),
                    _ => None,
                };
                let kind = if p.is_ip() {
                    "direct"
                } else if p.is_relay() {
                    "relay"
                } else {
                    "unknown"
                };
                (kind, rtt_ms, relay)
            })
        };
        if let Some((kind, rtt_ms, relay)) = selected {
            return Some(PathInfo {
                path: kind,
                rtt_ms: Some(rtt_ms),
                relay,
            });
        }

        // 回退：还没有选定路径时，用 remote_info 的活跃地址判断类型（无 RTT）。
        let info = self.endpoint.remote_info(target).await?;
        let mut has_direct = false;
        let mut has_relay = false;
        let mut relay_host = None;
        for a in info.addrs() {
            if !matches!(a.usage(), iroh::endpoint::TransportAddrUsage::Active) {
                continue;
            }
            match a.addr() {
                iroh::TransportAddr::Ip(_) => has_direct = true,
                iroh::TransportAddr::Relay(url) => {
                    has_relay = true;
                    if relay_host.is_none() {
                        relay_host = url.host_str().map(|h| h.to_string());
                    }
                }
                _ => {}
            }
        }
        let path = if has_direct {
            "direct"
        } else if has_relay {
            "relay"
        } else {
            "unknown"
        };
        Some(PathInfo {
            path,
            rtt_ms: None,
            relay: if path == "relay" { relay_host } else { None },
        })
    }
}

/// 到 B 的连接质量快照，供管理页展示路径徽章与延迟。
#[derive(Clone, Serialize)]
struct PathInfo {
    /// 穿透路径：direct（P2P 直连）/ relay（经中继）/ unknown。
    path: &'static str,
    /// 已选路径的往返延迟（毫秒）；仅有活跃路径时可得。
    rtt_ms: Option<u64>,
    /// 经中继时的中继主机名（direct 时为 None）。
    relay: Option<String>,
}

/// 一条控制台事件：供管理页“事件”页只读展示近期发生了什么，
/// 便于用户在不看终端日志的情况下排查连接与隧道问题。
#[derive(Clone, Serialize)]
struct Event {
    /// unix 毫秒时间戳。
    at: u64,
    /// 级别：info / warn / error，仅用于前端着色。
    level: &'static str,
    /// 事件分类（tunnel / reconnect / credential / mapping），供前端筛选或图标。
    kind: &'static str,
    /// 人类可读的事件描述（已脱敏，不含 token）。
    message: String,
}

/// 近期事件的有界环形缓冲：只保留最新 N 条，读写用轻量 Mutex 保护。
/// 纯内存、不落盘，进程退出即清空——它是排查辅助，不是审计副本。
struct EventLog {
    events: std::sync::Mutex<std::collections::VecDeque<Event>>,
    capacity: usize,
}

impl EventLog {
    fn new(capacity: usize) -> Arc<EventLog> {
        Arc::new(EventLog {
            events: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(capacity)),
            capacity,
        })
    }

    /// 追加一条事件；超过容量时丢弃最旧的。message 已由调用方脱敏。
    fn push(&self, level: &'static str, kind: &'static str, message: impl Into<String>) {
        let event = Event {
            at: now_unix_millis(),
            level,
            kind,
            message: message.into(),
        };
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() >= self.capacity {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// 返回最新在前的事件快照。
    fn snapshot(&self) -> Vec<Event> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events.iter().rev().cloned().collect()
    }
}

/// 单条映射的流量统计（按块增量累加，实时可见）。
struct Stats {
    tx: AtomicU64,           // 本地 -> 远端（上行）
    rx: AtomicU64,           // 远端 -> 本地（下行）
    active_conns: AtomicU64, // 当前活跃连接数（gauge，进出隧道时增减）
    /// 下一个连接序号（单调递增，仅用于给活跃连接一个稳定的展示 id）。
    next_conn_id: AtomicU64,
    /// 当前活跃连接明细：连接序号 → 元数据（来源、起始时间、独立字节计数）。
    /// 连接建立时登记、结束时由守卫移除，供管理页展开查看“哪条连接在忙”。
    conns: std::sync::Mutex<BTreeMap<u64, Arc<ConnMeta>>>,
    diagnostics: RwLock<MappingDiagnostics>,
}

/// 单条活跃连接的元数据。tx/rx 是这条连接自己的字节计数，接入 copy_count 的计数器切片，
/// 与映射级累计各自独立累加。
struct ConnMeta {
    /// 本地端连接来源（127/8 上的临时端口），用于区分并发连接。
    peer: String,
    /// 连接建立时间（unix 毫秒）。
    started_at: u64,
    tx: AtomicU64,
    rx: AtomicU64,
}

/// 活跃连接守卫：进入隧道处理时把连接登记进 active_conns 与明细表，
/// 任务结束（正常或 panic）时移除，保证 gauge 与明细都不会因异常路径而泄漏。
struct ActiveGuard {
    stats: Arc<Stats>,
    id: u64,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.stats.active_conns.fetch_sub(1, Ordering::Relaxed);
        self.stats
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

/// 一条活跃连接的只读快照，供 /api/stats 展开明细。
#[derive(Clone, Serialize)]
struct ConnSnapshot {
    id: u64,
    peer: String,
    started_at: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Clone, Serialize)]
struct TunnelFailure {
    reason: String,
    at: u64,
}

#[derive(Clone, Copy, Default)]
enum TunnelOutcome {
    #[default]
    None,
    Success,
    Failure,
}

#[derive(Default)]
struct MappingDiagnostics {
    listener_active: bool,
    /// 是否被用户停用；停用后不绑定本地端口，状态显示为 disabled。
    disabled: bool,
    last_tunnel_failure: Option<TunnelFailure>,
    last_tunnel_success_at: Option<u64>,
    last_outcome: TunnelOutcome,
}

impl Stats {
    fn new() -> Arc<Stats> {
        Stats::with_state(true, false)
    }

    /// 按初始运行态构造：`listener_active` 表示监听是否在跑，`disabled` 表示是否被用户停用。
    fn with_state(listener_active: bool, disabled: bool) -> Arc<Stats> {
        Arc::new(Stats {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            active_conns: AtomicU64::new(0),
            next_conn_id: AtomicU64::new(1),
            conns: std::sync::Mutex::new(BTreeMap::new()),
            diagnostics: RwLock::new(MappingDiagnostics {
                listener_active,
                disabled,
                ..Default::default()
            }),
        })
    }

    /// 登记一条新连接，返回其序号与独立字节计数器（接入 copy_count 用）。
    fn register_conn(&self, peer: String) -> (u64, Arc<ConnMeta>) {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let meta = Arc::new(ConnMeta {
            peer,
            started_at: now_unix_millis(),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
        });
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, meta.clone());
        (id, meta)
    }

    /// 当前活跃连接明细快照（按连接序号升序，即建立先后）。
    fn conn_snapshot(&self) -> Vec<ConnSnapshot> {
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(id, meta)| ConnSnapshot {
                id: *id,
                peer: meta.peer.clone(),
                started_at: meta.started_at,
                tx_bytes: meta.tx.load(Ordering::Relaxed),
                rx_bytes: meta.rx.load(Ordering::Relaxed),
            })
            .collect()
    }

    async fn record_success(&self) {
        let mut diagnostics = self.diagnostics.write().await;
        diagnostics.last_tunnel_success_at = Some(now_unix_millis());
        diagnostics.last_outcome = TunnelOutcome::Success;
    }

    async fn record_failure(&self, error: &anyhow::Error) {
        let mut diagnostics = self.diagnostics.write().await;
        diagnostics.last_tunnel_failure = Some(TunnelFailure {
            reason: diagnostic_reason(error),
            at: now_unix_millis(),
        });
        diagnostics.last_outcome = TunnelOutcome::Failure;
    }

    async fn mark_listener_stopped(&self) {
        self.diagnostics.write().await.listener_active = false;
    }

    async fn diagnostic_snapshot(&self) -> MappingDiagnosticSnapshot {
        let diagnostics = self.diagnostics.read().await;
        let state = if diagnostics.disabled {
            "disabled"
        } else if !diagnostics.listener_active {
            "stopped"
        } else {
            match diagnostics.last_outcome {
                TunnelOutcome::None => "listening",
                TunnelOutcome::Success => "active",
                TunnelOutcome::Failure => "degraded",
            }
        };
        MappingDiagnosticSnapshot {
            listener_active: diagnostics.listener_active,
            state,
            last_tunnel_failure: diagnostics.last_tunnel_failure.clone(),
            last_tunnel_success_at: diagnostics.last_tunnel_success_at,
        }
    }
}

#[derive(Serialize)]
struct MappingDiagnosticSnapshot {
    listener_active: bool,
    state: &'static str,
    last_tunnel_failure: Option<TunnelFailure>,
    last_tunnel_success_at: Option<u64>,
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn diagnostic_reason(error: &anyhow::Error) -> String {
    const MAX_CHARS: usize = 240;
    let message = error.to_string();
    let reason: String = message.chars().take(MAX_CHARS).collect();
    if message.chars().count() > MAX_CHARS {
        format!("{reason}...")
    } else {
        reason
    }
}

/// 一条映射的运行期把手：监听任务句柄、流量统计、取消令牌（用于 drain 在途连接）。
struct MappingHandle {
    /// 监听地址不可变；目标可在导入时原子更新，无需释放并重新绑定同一端口。
    mapping: Arc<RwLock<config::Mapping>>,
    task: JoinHandle<()>,
    stats: Arc<Stats>,
    cancel: CancellationToken,
}

struct Inner {
    mappings: HashMap<String, MappingHandle>,
}

type DomainListenerFuture = Pin<Box<dyn Future<Output = io::Result<TcpListener>> + Send>>;
type DomainListenerFactory = Arc<dyn Fn() -> DomainListenerFuture + Send + Sync>;
type DomainAdminCheck = Arc<dyn Fn() -> Result<(), DomainAuthorityError> + Send + Sync>;
type DomainPreflightFuture = Pin<Box<dyn Future<Output = Result<(), (StatusCode, String)>> + Send>>;
type DomainPreflight = Arc<dyn Fn(&config::DomainMapping) -> DomainPreflightFuture + Send + Sync>;

/// Why this process cannot safely manage the system-level domain mapping resources.
#[derive(Debug, Clone, Copy)]
enum DomainAuthorityError {
    NotAdministrator,
    #[allow(dead_code)] // Constructed on non-macOS/Linux builds.
    UnsupportedPlatform,
}

impl std::fmt::Display for DomainAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAdministrator => write!(
                f,
                "域名映射需要以管理员权限启动 PowerMap；请提升当前进程后重试"
            ),
            Self::UnsupportedPlatform => write!(
                f,
                "当前平台不支持域名映射；仅 macOS 和 Linux 支持受管 hosts 文件"
            ),
        }
    }
}

/// Checks only the authority of the current process. PowerMap never invokes a shell or elevates.
fn current_process_admin() -> Result<(), DomainAuthorityError> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if unsafe { libc::geteuid() } == 0 {
            Ok(())
        } else {
            Err(DomainAuthorityError::NotAdministrator)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(DomainAuthorityError::UnsupportedPlatform)
    }
}

fn system_domain_listener() -> DomainListenerFactory {
    Arc::new(|| Box::pin(async { TcpListener::bind("127.0.0.1:443").await }))
}

fn domain_preflight(link: Link) -> DomainPreflight {
    Arc::new(move |mapping| {
        let link = link.clone();
        let mapping = mapping.clone();
        Box::pin(async move { preflight_domain_mapping(&link, &mapping).await })
    })
}

/// Runtime state for a domain mapping. It is intentionally separate from ordinary port mappings:
/// its listener always belongs to loopback HTTPS and its hosts ownership must be tracked.
struct DomainMappingHandle {
    mapping: Arc<RwLock<config::DomainMapping>>,
    stats: Arc<Stats>,
    hosts_managed: Arc<AtomicBool>,
    local_listener: bool,
    conn_sem: Option<Arc<Semaphore>>,
    last_error: Arc<RwLock<Option<String>>>,
}

/// The one loopback HTTPS socket shared by all enabled domain mappings.
struct SharedDomainListener {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

struct DomainInner {
    mappings: HashMap<String, Arc<DomainMappingHandle>>,
    listener: Option<SharedDomainListener>,
}

#[derive(Clone)]
struct AppState {
    link: Link,
    web_bind: String,
    web_token: String,
    web_tls_cert: String,
    web_tls_key: String,
    max_mappings: usize,
    max_conns_per_mapping: usize,
    domains: Arc<Mutex<DomainInner>>,
    /// Domain resource changes touch shared hosts state and loopback port 443.
    /// A single bounded lock avoids an attacker growing a per-domain lock map indefinitely.
    domain_lifecycle: Arc<Mutex<()>>,
    hosts: HostsStore,
    domain_listener: DomainListenerFactory,
    domain_admin_check: DomainAdminCheck,
    domain_preflight: DomainPreflight,
    config_path: PathBuf,
    metrics: Arc<Metrics>,
    events: Arc<EventLog>,
    inner: Arc<Mutex<Inner>>,
    updater: update::UpdateCoordinator,
    /// 反向映射策略（deny-all）：是否接受 B 端发起的反向隧道，及允许 A 拨号的目标。
    /// 用 RwLock 承载，便于后续通过管理页在运行期开关；save/export 从此读回持久化。
    reverse: Arc<RwLock<ReverseConfig>>,
}

/// A 端反向映射运行期配置。空网段/端口即 deny-all（见 [`tunnel::ReversePolicy`]）。
///
/// 同时作为 `GET`/`PUT /api/reverse` 的 JSON 线格式：内存态与线格式字段完全一致，
/// 故用同一个类型，避免内存态 / 视图两副本各自维护。
#[derive(Clone, Default, Serialize, Deserialize)]
struct ReverseConfig {
    enabled: bool,
    allow_networks: Vec<String>,
    allow_ports: Vec<u16>,
}

impl ReverseConfig {
    fn policy(&self) -> tunnel::ReversePolicy {
        tunnel::ReversePolicy::from_config(self.enabled, &self.allow_networks, &self.allow_ports)
    }
}

/// 在一条已有的连接上开流并完成握手。流类型是 noq 的私有类型，对外用 trait 对象承载。
async fn open_tunnel(
    conn: &Connection,
    req: &proto::OpenRequest,
) -> Result<(
    Box<dyn AsyncWrite + Unpin + Send>,
    Box<dyn AsyncRead + Unpin + Send>,
)> {
    let (mut send, mut recv) = conn.open_bi().await.context("打开隧道流失败")?;
    proto::write_open(&mut send, req).await?;
    proto::read_status(&mut recv)
        .await?
        .map_err(|m| anyhow::anyhow!("B 拒绝: {m}"))?;
    Ok((Box::new(send), Box::new(recv)))
}

/// 建立隧道（连接/握手失败时重连重试一次）。
async fn open_with_retry(
    link: &Link,
    req: &proto::OpenRequest,
) -> Result<(
    Box<dyn AsyncWrite + Unpin + Send>,
    Box<dyn AsyncRead + Unpin + Send>,
)> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..2u8 {
        let conn = match link.get().await {
            Ok(c) => c,
            Err(e) => {
                last = Some(e);
                continue;
            }
        };
        match open_tunnel(&conn, req).await {
            Ok(pair) => return Ok(pair),
            Err(e) => {
                link.invalidate().await;
                tracing::warn!(attempt, error = %e, "握手失败，重试");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("无法建立隧道")))
}

/// 一条 TCP / HTTP 隧道：开流、握手、本地与远端双向透传（优雅半关闭 + 流量计数 + 全局指标）。
/// conn 是这条连接自己的元数据；其 tx/rx 与映射级累计并行累加，供管理页展开明细。
///
/// `prefix` 是已从本地连接读出、需要先补发给远端的字节（HTTP 网关在窥探 Host 头后
/// 用它把读走的请求头重放给后端）；普通 TCP 传空切片。
async fn handle_tunnel(
    link: Link,
    req: proto::OpenRequest,
    local: TcpStream,
    stats: Arc<Stats>,
    conn: Arc<ConnMeta>,
    metrics: Arc<Metrics>,
    prefix: Vec<u8>,
) -> Result<()> {
    let (mut send, mut recv) = open_with_retry(&link, &req).await?;
    metrics.tunnel_open();
    stats.record_success().await;
    let (mut l_read, mut l_write) = tokio::io::split(local);
    let up = async {
        if !prefix.is_empty() {
            send.write_all(&prefix).await?;
            let n = prefix.len() as u64;
            stats.tx.fetch_add(n, Ordering::Relaxed);
            conn.tx.fetch_add(n, Ordering::Relaxed);
            metrics.bytes_tx.fetch_add(n, Ordering::Relaxed);
        }
        tunnel::copy_count(
            &mut l_read,
            &mut send,
            &[&stats.tx, &conn.tx, &metrics.bytes_tx],
        )
        .await?;
        send.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let down = async {
        tunnel::copy_count(
            &mut recv,
            &mut l_write,
            &[&stats.rx, &conn.rx, &metrics.bytes_rx],
        )
        .await?;
        l_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::try_join!(up, down);
    metrics.tunnel_close();
    result.map(|_| ())
}

// ---- HTTP handlers ----

async fn index() -> Html<&'static str> {
    Html(include_str!("web/index.html"))
}

async fn metrics_handler(State(st): State<AppState>) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4")],
        st.metrics.render(),
    )
}

#[derive(Serialize)]
struct Status {
    connected: bool,
    configured: bool,
    node_id: String,
    mappings: usize,
    /// 穿透路径：direct（P2P 打洞直连）/ relay（经中继转发）/ unknown；未连接时为 null。
    path: Option<&'static str>,
    /// 已选路径的往返延迟（毫秒）；无活跃路径时为 null。
    rtt_ms: Option<u64>,
    /// 经中继时的中继主机名；直连或未知时为 null。
    relay: Option<String>,
    /// 二进制版本（Cargo.toml 的 package version），供管理页展示。
    version: &'static str,
    /// 当前活跃隧道数（瞬时量）。区别于 mappings：后者是已配置的映射条数。
    active_tunnels: u64,
    /// 累计成功建立的隧道数。
    tunnels_opened: u64,
    /// 累计建立失败的隧道数。
    tunnels_failed: u64,
    /// 看门狗重连累计次数。
    reconnects: u64,
    /// 因并发上限被拒累计数。
    over_limit: u64,
    /// 当前连接建立时刻（unix 毫秒）；未连接时为 null，供管理页展示"已连接时长"。
    connected_since: Option<u64>,
    /// 当前活跃连接中可确认的远端直连 IP；经中继时可能为空。
    connected_ips: Vec<String>,
}

async fn status(State(st): State<AppState>) -> Json<Status> {
    let n = st.inner.lock().await.mappings.len();
    let path_info = st.link.transport_path().await;
    let creds = st.link.creds.read().await;
    let m = &st.metrics;
    let (path, rtt_ms, relay) = match path_info {
        Some(p) => (Some(p.path), p.rtt_ms, p.relay),
        None => (None, None, None),
    };
    let connected = st.link.is_alive().await;
    let connected_since = if connected {
        match st.link.connected_since.load(Ordering::Relaxed) {
            0 => None,
            since => Some(since),
        }
    } else {
        None
    };
    let connected_ips = if connected {
        st.link.connected_ips().await
    } else {
        Vec::new()
    };
    Json(Status {
        connected,
        configured: creds.target.is_some(),
        node_id: creds.node_id.clone(),
        mappings: n,
        path,
        rtt_ms,
        relay,
        version: env!("CARGO_PKG_VERSION"),
        active_tunnels: m.tunnels_active.load(Ordering::Relaxed),
        tunnels_opened: m.tunnels_opened.load(Ordering::Relaxed),
        tunnels_failed: m.tunnels_failed.load(Ordering::Relaxed),
        reconnects: m.reconnects.load(Ordering::Relaxed),
        over_limit: m.over_limit.load(Ordering::Relaxed),
        connected_since,
        connected_ips,
    })
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use serde_json::Value;
    use tower::ServiceExt;

    static TEST_STATE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    async fn test_state(web_token: &str) -> AppState {
        let endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = format!(
            "{suffix}-{}",
            TEST_STATE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        AppState {
            link: Link {
                endpoint,
                creds: Arc::new(RwLock::new(Creds::default())),
                conn: Arc::new(Mutex::new(None)),
                connected_since: Arc::new(AtomicU64::new(0)),
            },
            web_bind: "127.0.0.1:0".into(),
            web_token: web_token.into(),
            web_tls_cert: String::new(),
            web_tls_key: String::new(),
            max_mappings: 8,
            max_conns_per_mapping: 8,
            domains: Arc::new(Mutex::new(DomainInner {
                mappings: HashMap::new(),
                listener: None,
            })),
            domain_lifecycle: Arc::new(Mutex::new(())),
            hosts: {
                let path = std::env::temp_dir().join(format!("powermap-hosts-test-{suffix}"));
                std::fs::write(&path, "").unwrap();
                HostsStore::at(path)
            },
            domain_listener: Arc::new(|| {
                Box::pin(async { TcpListener::bind("127.0.0.1:0").await })
            }),
            domain_admin_check: Arc::new(|| Ok(())),
            domain_preflight: Arc::new(|_| {
                Box::pin(async {
                    Err((
                        StatusCode::BAD_GATEWAY,
                        "test state has no configured domain preflight".into(),
                    ))
                })
            }),
            config_path: std::env::temp_dir().join(format!("powermap-client-test-{suffix}.toml")),
            metrics: Metrics::new(),
            events: EventLog::new(200),
            inner: Arc::new(Mutex::new(Inner {
                mappings: HashMap::new(),
            })),
            updater: update::UpdateCoordinator::new(CancellationToken::new()),
            reverse: Arc::new(RwLock::new(ReverseConfig::default())),
        }
    }

    #[tokio::test]
    async fn save_config_preserves_loaded_domain_mappings() {
        let state = test_state("").await;
        let domain_mappings = vec![config::DomainMapping::new("ai-router.dl-aiot.com")];
        state.domains.lock().await.mappings.insert(
            domain_mappings[0].domain.clone(),
            disabled_domain_handle(domain_mappings[0].clone(), false, None),
        );

        save_config(&state).await;

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(saved.domain_mappings, domain_mappings);
        std::fs::remove_file(&state.config_path).unwrap();
    }

    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn authenticated_post(uri: &str, body: &'static str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn domain_mapping_api_rejects_invalid_domain_before_system_mutation() {
        let app = app(test_state("admin-token").await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"domain":"*.bad"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn domain_mapping_api_creates_a_disabled_record_without_system_mutation() {
        let state = test_state("admin-token").await;
        let hosts = state.hosts.clone();
        let app = app(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"domain":"api.example.test","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created = response_json(response).await;
        assert_eq!(created["enabled"], false);
        assert_eq!(created["hosts_managed"], false);
        assert!(!hosts.has_loopback("api.example.test").unwrap());

        let listed = response_json(
            app.oneshot(
                Request::get("/api/domain-mappings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn domain_mapping_put_keeps_remote_port_when_omitted() {
        let state = test_state("admin-token").await;
        let mapping = config::DomainMapping {
            domain: "api.example.test".into(),
            remote_port: 8443,
            enabled: false,
        };
        state.domains.lock().await.mappings.insert(
            mapping.domain.clone(),
            disabled_domain_handle(mapping, false, None),
        );
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/domain-mappings/api.example.test")
                    .header(header::AUTHORIZATION, "Bearer admin-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"domain":"api.example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["remote_port"], 8443);
    }

    #[tokio::test]
    async fn enabled_domain_port_change_preflights_before_persisting() {
        use std::sync::atomic::AtomicUsize;

        let mut state = test_state("admin-token").await;
        let preflight_calls = Arc::new(AtomicUsize::new(0));
        state.domain_preflight = {
            let preflight_calls = preflight_calls.clone();
            Arc::new(move |_| {
                preflight_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Err((
                        StatusCode::BAD_GATEWAY,
                        "preflight deliberately failed".into(),
                    ))
                })
            })
        };
        let mapping = config::DomainMapping::new("api.example.test");
        state.domains.lock().await.mappings.insert(
            mapping.domain.clone(),
            disabled_domain_handle(mapping, false, None),
        );
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/domain-mappings/api.example.test")
                    .header(header::AUTHORIZATION, "Bearer admin-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"domain":"api.example.test","remote_port":8443}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(preflight_calls.load(Ordering::SeqCst), 1);
        let persisted = state.domains.lock().await.mappings["api.example.test"]
            .mapping
            .read()
            .await
            .clone();
        assert_eq!(persisted.remote_port, 443);
    }

    #[tokio::test]
    async fn active_domain_mappings_share_one_loopback_listener_and_hosts_entries() {
        use std::sync::atomic::AtomicUsize;

        let mut state = test_state("admin-token").await;
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let hosts = state.hosts.clone();
        let binds = Arc::new(AtomicUsize::new(0));
        state.domain_listener = {
            let binds = binds.clone();
            Arc::new(move || {
                binds.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { TcpListener::bind("127.0.0.1:0").await })
            })
        };
        let app = app(state.clone());

        let first = app
            .clone()
            .oneshot(authenticated_post(
                "/api/domain-mappings",
                r#"{"domain":"one.example.test"}"#,
            ))
            .await
            .unwrap();
        let second = app
            .clone()
            .oneshot(authenticated_post(
                "/api/domain-mappings",
                r#"{"domain":"two.example.test"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(binds.load(Ordering::SeqCst), 1);
        assert!(hosts.has_loopback("one.example.test").unwrap());
        assert!(hosts.has_loopback("two.example.test").unwrap());
        let domains = state.domains.lock().await;
        assert!(domains.listener.is_some());
        assert!(
            domains
                .mappings
                .values()
                .all(|handle| handle.local_listener)
        );
        drop(domains);

        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/domain-mappings/one.example.test/toggle")
                        .header(header::AUTHORIZATION, "Bearer admin-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(state.domains.lock().await.listener.is_some());
        assert_eq!(
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings/two.example.test/toggle")
                    .header(header::AUTHORIZATION, "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status(),
            StatusCode::OK
        );
        assert!(state.domains.lock().await.listener.is_none());
    }

    fn tls_client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0, 0x2f]);
        body.extend_from_slice(&[1, 0]);
        let sni_extension_len = 5 + name.len();
        let extensions_len = 4 + sni_extension_len;
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&(sni_extension_len as u16).to_be_bytes());
        body.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(name);

        let mut handshake = vec![1];
        let len = body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn tls_sni_parser_normalizes_and_rejects_malformed_names() {
        assert_eq!(
            parse_tls_client_hello_sni(&tls_client_hello("Api.Example.Test")).unwrap(),
            "api.example.test"
        );
        assert!(parse_tls_client_hello_sni(&tls_client_hello("bad_name.example")).is_err());
        assert!(parse_tls_client_hello_sni(&[22, 3, 1, 0, 1, 1]).is_err());
    }

    #[test]
    fn domain_handshake_limiter_rejects_connections_at_capacity() {
        let limiter = Arc::new(Semaphore::new(1));
        let first = try_acquire_domain_handshake_slot(&limiter).unwrap();

        assert!(try_acquire_domain_handshake_slot(&limiter).is_none());
        drop(first);
        assert!(try_acquire_domain_handshake_slot(&limiter).is_some());
    }

    #[tokio::test]
    async fn tls_sni_read_replays_every_consumed_clienthello_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = tls_client_hello("api.example.test");
        let expected_for_server = expected.clone();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let (sni, prefix) = read_tls_client_hello_prefix(&mut tcp).await.unwrap();
            assert_eq!(sni, "api.example.test");
            prefix
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&expected).await.unwrap();
        drop(client);
        assert_eq!(server.await.unwrap(), expected_for_server);
    }

    #[tokio::test]
    async fn listener_bind_failure_does_not_write_a_hosts_marker() {
        let mut state = test_state("admin-token").await;
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let hosts = state.hosts.clone();
        state.domain_listener = Arc::new(|| {
            Box::pin(async { Err(io::Error::new(io::ErrorKind::AddrInUse, "test conflict")) })
        });
        let app = app(state);

        let response = app
            .oneshot(authenticated_post(
                "/api/domain-mappings",
                r#"{"domain":"api.example.test"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(!hosts.has_loopback("api.example.test").unwrap());
    }

    #[tokio::test]
    async fn domain_mapping_creation_respects_max_mappings() {
        let mut state = test_state("admin-token").await;
        state.max_mappings = 1;
        let app = app(state);
        let first = app
            .clone()
            .oneshot(authenticated_post(
                "/api/domain-mappings",
                r#"{"domain":"one.example.test","enabled":false}"#,
            ))
            .await
            .unwrap();
        let second = app
            .oneshot(authenticated_post(
                "/api/domain-mappings",
                r#"{"domain":"two.example.test","enabled":false}"#,
            ))
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn enabling_a_domain_mapping_requires_current_process_administrator_authority() {
        let mut state = test_state("admin-token").await;
        let hosts = state.hosts.clone();
        state.domain_admin_check = Arc::new(|| Err(DomainAuthorityError::NotAdministrator));
        let app = app(state);
        let created = app
            .clone()
            .clone()
            .clone()
            .oneshot(authenticated_post(
                "/api/domain-mappings",
                r#"{"domain":"api.example.test","enabled":false}"#,
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);

        let enabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings/api.example.test/toggle")
                    .header(header::AUTHORIZATION, "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enabled.status(), StatusCode::FORBIDDEN);
        assert!(!hosts.has_loopback("api.example.test").unwrap());
        let listed = response_json(
            app.oneshot(
                Request::get("/api/domain-mappings")
                    .header(header::AUTHORIZATION, "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(listed[0]["enabled"], false);
    }

    #[tokio::test]
    async fn failed_disable_cleanup_preserves_retryable_hosts_error_state() {
        let mut state = test_state("admin-token").await;
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let original_hosts = state.hosts.clone();
        let mapping = config::DomainMapping::new("api.example.test");
        let handle = start_domain_mapping_owned(&state, mapping.clone())
            .await
            .unwrap();
        state
            .domains
            .lock()
            .await
            .mappings
            .insert(mapping.domain.clone(), handle);
        assert!(original_hosts.has_loopback(&mapping.domain).unwrap());

        // Simulate a hosts store that fails during cleanup after a successful activation.
        let missing_hosts = state.config_path.with_extension("missing-hosts");
        let _ = std::fs::remove_file(&missing_hosts);
        state.hosts = HostsStore::at(missing_hosts);
        let response = toggle_domain_mapping(State(state.clone()), Path(mapping.domain.clone()))
            .await
            .unwrap()
            .0;
        assert!(!response.enabled);
        assert!(response.hosts_managed);
        assert!(response.last_error.is_some());

        let status = list_domain_mappings(State(state.clone())).await.0;
        assert!(status[0].hosts_managed);
        assert!(status[0].last_error.as_deref().unwrap().contains("hosts"));
        let mut saved = build_config(&state).await;
        assert!(!saved.domain_mappings[0].enabled);

        // A restarted runtime can detect the retained exact marker and presents it for retry.
        let mut restarted = test_state("").await;
        restarted.hosts = original_hosts;
        let recovered = start_domain_mapping_owned(&restarted, saved.domain_mappings.remove(0))
            .await
            .unwrap();
        let recovered_status = domain_status(&recovered).await;
        assert!(recovered_status.hosts_managed);
        assert!(recovered_status.last_error.is_some());
    }

    #[tokio::test]
    async fn failed_delete_cleanup_persists_disabled_recovery_state() {
        let mut state = test_state("admin-token").await;
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let original_hosts = state.hosts.clone();
        let mapping = config::DomainMapping::new("delete.example.test");
        let handle = start_domain_mapping_owned(&state, mapping.clone())
            .await
            .unwrap();
        state
            .domains
            .lock()
            .await
            .mappings
            .insert(mapping.domain.clone(), handle);
        save_config(&state).await;

        let missing_hosts = state.config_path.with_extension("missing-hosts");
        let _ = std::fs::remove_file(&missing_hosts);
        state.hosts = HostsStore::at(missing_hosts);
        let response = remove_domain_mapping(State(state.clone()), Path(mapping.domain.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(saved.domain_mappings.len(), 1);
        assert!(!saved.domain_mappings[0].enabled);

        let mut restarted = test_state("").await;
        restarted.hosts = original_hosts;
        let recovered = start_domain_mapping_owned(&restarted, saved.domain_mappings[0].clone())
            .await
            .unwrap();
        let status = domain_status(&recovered).await;
        assert!(!status.enabled);
        assert!(status.hosts_managed);
        assert!(status.last_error.is_some());
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn concurrent_create_does_not_rollback_the_published_mapping_hosts_marker() {
        use std::sync::atomic::AtomicUsize;

        let mut state = test_state("admin-token").await;
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let hosts = state.hosts.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_entered = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        state.domain_listener = {
            let calls = calls.clone();
            let first_entered = first_entered.clone();
            let release_first = release_first.clone();
            Arc::new(move || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                let first_entered = first_entered.clone();
                let release_first = release_first.clone();
                Box::pin(async move {
                    if call == 0 {
                        first_entered.notify_one();
                        release_first.notified().await;
                        TcpListener::bind("127.0.0.1:0").await
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "simulated bind conflict",
                        ))
                    }
                })
            })
        };
        let app = app(state);
        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(authenticated_post(
                    "/api/domain-mappings",
                    r#"{"domain":"api.example.test"}"#,
                ))
                .await
                .unwrap()
        });
        first_entered.notified().await;

        let second_app = app.clone();
        let second = tokio::spawn(async move {
            second_app
                .oneshot(authenticated_post(
                    "/api/domain-mappings",
                    r#"{"domain":"api.example.test"}"#,
                ))
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release_first.notify_one();

        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        assert_eq!(second.await.unwrap().status(), StatusCode::CONFLICT);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(hosts.has_loopback("api.example.test").unwrap());
    }

    fn http_mapping(routes: Vec<config::HttpRoute>) -> config::Mapping {
        config::Mapping {
            local: "127.0.0.1:8080".into(),
            host: "10.0.0.1".into(),
            port: 80,
            enabled: true,
            name: String::new(),
            mode: config::MappingMode::Http,
            routes,
        }
    }

    #[test]
    fn parse_host_header_reads_the_host_line_case_insensitively() {
        let req = b"GET / HTTP/1.1\r\nHOST: grafana.local:3000\r\nAccept: */*\r\n\r\n";
        assert_eq!(
            parse_host_header(req).as_deref(),
            Some("grafana.local:3000")
        );
        // 没有 Host 头
        assert_eq!(parse_host_header(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn select_http_backend_matches_host_then_falls_back() {
        let mapping = http_mapping(vec![
            config::HttpRoute {
                host_match: "grafana.local".into(),
                target_host: "192.168.1.10".into(),
                target_port: 3000,
            },
            config::HttpRoute {
                host_match: String::new(), // 兜底
                target_host: "192.168.1.99".into(),
                target_port: 8080,
            },
        ]);
        // 命中具名路由（Host 头带端口也应忽略端口匹配）
        assert_eq!(
            select_http_backend(&mapping, Some("grafana.local:3000")),
            ("192.168.1.10".into(), 3000)
        );
        // 未命中 → 兜底路由
        assert_eq!(
            select_http_backend(&mapping, Some("unknown.local")),
            ("192.168.1.99".into(), 8080)
        );
        // 无 Host → 兜底路由
        assert_eq!(
            select_http_backend(&mapping, None),
            ("192.168.1.99".into(), 8080)
        );
    }

    #[test]
    fn select_http_backend_without_routes_uses_mapping_target() {
        let mapping = http_mapping(vec![]);
        assert_eq!(
            select_http_backend(&mapping, Some("anything.local")),
            ("10.0.0.1".into(), 80)
        );
    }

    #[tokio::test]
    async fn mappings_api_creates_lists_and_removes_a_real_listener() {
        let state = test_state("").await;
        let app = app(state);
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
            )))
            .unwrap();
        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let listed = app
            .clone()
            .oneshot(Request::get("/api/mappings").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let mappings = response_json(listed).await;
        assert_eq!(mappings.as_array().unwrap().len(), 1);
        assert_eq!(mappings[0]["local"], local.to_string());

        let delete = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/mappings/{local}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn update_retargets_in_place_and_rebinds_a_new_local_address() {
        let state = test_state("").await;
        let app = app(state);
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::OK
        );

        // 仅改目标：本地地址不变，复用监听。
        let retarget = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/mappings/{local}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"{local}","host":"127.0.0.1","port":5432}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retarget.status(), StatusCode::OK);
        let listed = response_json(
            app.clone()
                .oneshot(Request::get("/api/mappings").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["local"], local.to_string());
        assert_eq!(listed[0]["port"], 5432);

        // 改本地地址：绑定新地址、释放旧地址。
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let new_local = reserved.local_addr().unwrap();
        drop(reserved);
        let rebind = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/mappings/{local}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"{new_local}","host":"127.0.0.1","port":5432}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rebind.status(), StatusCode::OK);
        let listed = response_json(
            app.clone()
                .oneshot(Request::get("/api/mappings").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["local"], new_local.to_string());
        // 旧地址已释放，可以重新绑定。
        TcpListener::bind(local).await.unwrap();
    }

    #[tokio::test]
    async fn toggle_disables_a_mapping_and_frees_its_local_port() {
        let state = test_state("").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::OK
        );

        // 停用：应释放本地端口，状态转为 disabled。
        let disabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/mappings/{local}/toggle"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::OK);
        let body = response_json(disabled).await;
        assert_eq!(body["enabled"], false);
        // 端口已释放：可重新绑定。停用需等待旧监听任务收尾，稍作重试。
        let mut rebound = false;
        for _ in 0..25 {
            if TcpListener::bind(local).await.is_ok() {
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rebound, "停用后本地端口应可重新绑定");

        let stats = response_json(
            app.clone()
                .oneshot(Request::get("/api/stats").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(stats[0]["state"], "disabled");
        assert_eq!(stats[0]["enabled"], false);

        // 再次 toggle：重新启用并绑回端口。
        let enabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/mappings/{local}/toggle"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enabled.status(), StatusCode::OK);
        assert_eq!(response_json(enabled).await["enabled"], true);
        // 重新启用后端口被映射占用，外部不能再绑定。
        assert!(TcpListener::bind(local).await.is_err());
    }

    #[tokio::test]
    async fn create_and_list_preserve_the_optional_mapping_name() {
        let state = test_state("").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"127.0.0.1","port":6379,"name":"Redis 主库"}}"#
            )))
            .unwrap();
        let created = response_json(app.clone().oneshot(create).await.unwrap()).await;
        assert_eq!(created["name"], "Redis 主库");

        let listed = response_json(
            app.oneshot(Request::get("/api/mappings").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed[0]["name"], "Redis 主库");
    }

    #[tokio::test]
    async fn toggle_all_disables_every_mapping_and_reports_counts() {
        let state = test_state("").await;
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_local = first.local_addr().unwrap();
        drop(first);
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_local = second.local_addr().unwrap();
        drop(second);
        let app = app(state);

        for local in [first_local, second_local] {
            let create = Request::builder()
                .method("POST")
                .uri("/api/mappings")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
                )))
                .unwrap();
            assert_eq!(
                app.clone().oneshot(create).await.unwrap().status(),
                StatusCode::OK
            );
        }

        // 全部停用：两条都从启用切到停用，changed=2。
        let disabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings/toggle-all")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::OK);
        let body = response_json(disabled).await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["changed"], 2);
        assert_eq!(body["failed"], 0);

        // 两个本地端口都应已释放。
        TcpListener::bind(first_local).await.unwrap();
        TcpListener::bind(second_local).await.unwrap();

        // 再次全部停用：都已是停用态，changed=0、unchanged=2。
        let again = response_json(
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings/toggle-all")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(again["changed"], 0);
        assert_eq!(again["unchanged"], 2);
    }

    #[tokio::test]
    async fn merge_import_keeps_existing_mappings_and_adds_new_ones() {
        let state = test_state("").await;
        let existing = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let existing_local = existing.local_addr().unwrap();
        drop(existing);
        let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let incoming_local = incoming.local_addr().unwrap();
        drop(incoming);
        let app = app(state);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{existing_local}","host":"127.0.0.1","port":6379}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::OK
        );

        // 合并导入一条新映射：不带凭证，只叠加映射。
        let import = Request::builder()
            .method("POST")
            .uri("/api/import?mode=merge")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "mappings": [{
                        "local": incoming_local.to_string(),
                        "host": "127.0.0.1",
                        "port": 5432,
                    }],
                })
                .to_string(),
            ))
            .unwrap();
        let result = response_json(app.clone().oneshot(import).await.unwrap()).await;
        assert_eq!(result["merged"], true);
        assert_eq!(result["kept"], 1); // 既有映射被保留
        assert_eq!(result["started"], 1); // 导入里 1 条

        // 合并后两条都在：既有的没有被删除。
        let listed = response_json(
            app.oneshot(Request::get("/api/mappings").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        let locals: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["local"].as_str().unwrap())
            .collect();
        assert_eq!(locals.len(), 2);
        assert!(locals.contains(&existing_local.to_string().as_str()));
        assert!(locals.contains(&incoming_local.to_string().as_str()));
    }

    #[tokio::test]
    async fn update_rejects_an_unknown_mapping() {
        let state = test_state("").await;
        let app = app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/mappings/127.0.0.1:1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:1","host":"127.0.0.1","port":6379}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn creating_a_mapping_records_an_event_and_reports_active_conns() {
        let state = test_state("").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::OK
        );

        // 新建映射即产生一条 mapping 事件，供“事件”页只读展示。
        let events = response_json(
            app.clone()
                .oneshot(Request::get("/api/events").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        let events = events.as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "mapping");
        assert!(
            events[0]["message"]
                .as_str()
                .unwrap()
                .contains(&local.to_string())
        );

        // 全新映射尚无连接，active_conns 应为 0（字段存在即验证已接线）。
        let stats = response_json(
            app.oneshot(Request::get("/api/stats").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(stats[0]["active_conns"], 0);
    }

    #[tokio::test]
    async fn mapping_stats_reports_listener_and_the_latest_tunnel_failure() {
        let state = test_state("").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::OK
        );

        let initial = response_json(
            app.clone()
                .oneshot(Request::get("/api/stats").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(initial[0]["listener_active"], true);
        assert_eq!(initial[0]["state"], "listening");
        assert!(initial[0]["last_tunnel_failure"].is_null());
        assert!(initial[0]["last_tunnel_success_at"].is_null());

        TcpStream::connect(local).await.unwrap();
        let mut failed = None;
        for _ in 0..25 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let stats = response_json(
                app.clone()
                    .oneshot(Request::get("/api/stats").body(Body::empty()).unwrap())
                    .await
                    .unwrap(),
            )
            .await;
            if !stats[0]["last_tunnel_failure"].is_null() {
                failed = Some(stats);
                break;
            }
        }
        let failed = failed.expect("the failed tunnel should be reported");
        assert_eq!(failed[0]["listener_active"], true);
        assert_eq!(failed[0]["state"], "degraded");
        assert_eq!(
            failed[0]["last_tunnel_failure"]["reason"],
            "尚未配置凭证：请在 Web 管理页粘贴 server 端的凭证"
        );
        assert!(failed[0]["last_tunnel_failure"]["at"].as_u64().is_some());
    }

    #[tokio::test]
    async fn mapping_mutations_are_available_without_web_token_authentication() {
        let state = test_state("admin-secret").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"{local}","host":"127.0.0.1","port":80}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);

        let removed = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/mappings/{local}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn mapping_preflight_explains_when_credentials_are_missing() {
        let state = test_state("").await;
        let app = app(state);
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings/preflight")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"{local}","host":"127.0.0.1","port":6379}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["ready"], false);
        assert_eq!(body["checks"]["local_listener"]["ok"], true);
        assert_eq!(body["checks"]["credential"]["ok"], false);
        assert!(
            body["checks"]["credential"]["detail"]
                .as_str()
                .unwrap()
                .contains("凭证")
        );
        assert_eq!(body["checks"]["target"]["ok"], false);
    }

    #[tokio::test]
    async fn status_exposes_connected_ip_list_for_the_console() {
        let app = app(test_state("").await);
        let response = app
            .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert!(body["connected_ips"].as_array().is_some());
    }

    #[tokio::test]
    async fn credential_view_preserves_published_targets_for_the_console() {
        let state = test_state("").await;
        let node_id = state.link.endpoint.id().to_string();
        let target = parse_target(&node_id).unwrap();
        state
            .link
            .set_creds(
                node_id,
                "test-token".into(),
                target,
                vec![config::PublishedTarget {
                    host: "192.168.1.101".into(),
                    port: 6379,
                    label: "Redis 主库".into(),
                }],
            )
            .await;
        let app = app(state);

        let response = app
            .oneshot(Request::get("/api/credential").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["published_targets"][0]["host"], "192.168.1.101");
        assert_eq!(body["published_targets"][0]["port"], 6379);
    }

    #[tokio::test]
    async fn node_api_reads_the_local_share_credential() {
        let state = test_state("").await;
        let credential_path = state.config_path.with_file_name("powermap.credential.json");
        std::fs::write(
            &credential_path,
            r#"{"node_id":"local-node","token":"local-token","published_targets":[]}"#,
        )
        .unwrap();

        let response = app(state)
            .oneshot(Request::get("/api/node").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = response_json(response).await;

        assert_eq!(body["configured"], true);
        assert_eq!(body["node_id"], "local-node");
        assert_eq!(body["token"], "local-token");
        std::fs::remove_file(credential_path).unwrap();
    }

    #[tokio::test]
    async fn failed_import_preserves_existing_mapping_and_credentials() {
        let state = test_state("").await;
        let old_target = state.link.endpoint.id();
        {
            let mut creds = state.link.creds.write().await;
            creds.node_id = old_target.to_string();
            creds.token = "old-token".into();
            creds.target = Some(old_target);
        }

        let reserved_old = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_local = reserved_old.local_addr().unwrap();
        drop(reserved_old);
        let old_mapping = config::Mapping {
            local: old_local.to_string(),
            host: "127.0.0.1".into(),
            port: 6379,
            enabled: true,
            name: String::new(),
            mode: config::MappingMode::default(),
            routes: vec![],
        };
        let old_handle = start_mapping_owned(&state, old_mapping.clone())
            .await
            .unwrap();
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(old_mapping.local.clone(), old_handle);

        // Keep this listener occupied so the imported mapping cannot be started.
        let blocked = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blocked_local = blocked.local_addr().unwrap();
        let new_target = Endpoint::builder(presets::N0).bind().await.unwrap();
        let app = app(state.clone());
        let import = Request::builder()
            .method("POST")
            .uri("/api/import")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "node_id": new_target.id().to_string(),
                    "token": "new-token",
                    "mappings": [{
                        "local": blocked_local.to_string(),
                        "host": "127.0.0.1",
                        "port": 5432,
                    }],
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(import).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let old_runtime_mapping = {
            let mappings = state.inner.lock().await;
            assert_eq!(mappings.mappings.len(), 1);
            mappings.mappings[&old_mapping.local].mapping.clone()
        };
        assert_eq!(*old_runtime_mapping.read().await, old_mapping);
        TcpStream::connect(old_local).await.unwrap();

        let creds = state.link.creds.read().await;
        assert_eq!(creds.node_id, old_target.to_string());
        assert_eq!(creds.token, "old-token");
    }
}

async fn list(State(st): State<AppState>) -> Json<Vec<config::Mapping>> {
    let mappings: Vec<Arc<RwLock<config::Mapping>>> = st
        .inner
        .lock()
        .await
        .mappings
        .values()
        .map(|h| h.mapping.clone())
        .collect();
    let mut result = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        result.push(mapping.read().await.clone());
    }
    Json(result)
}

/// A domain mapping's public lifecycle state. `local_listener` is true only while the
/// mapping owns its injected loopback listener; `hosts_managed` refers only to PowerMap's
/// exact marker, never an unrelated hosts-file entry.
#[derive(Serialize)]
pub struct DomainMappingStatus {
    domain: String,
    remote_port: u16,
    enabled: bool,
    hosts_managed: bool,
    local_listener: bool,
    last_error: Option<String>,
}

async fn domain_status(handle: &DomainMappingHandle) -> DomainMappingStatus {
    let mapping = handle.mapping.read().await;
    let diagnostics = handle.stats.diagnostic_snapshot().await;
    DomainMappingStatus {
        domain: mapping.domain.clone(),
        remote_port: mapping.remote_port,
        enabled: mapping.enabled,
        hosts_managed: handle.hosts_managed.load(Ordering::Relaxed),
        local_listener: handle.local_listener && diagnostics.listener_active,
        last_error: handle.last_error.read().await.clone(),
    }
}

async fn list_domain_mappings(State(st): State<AppState>) -> Json<Vec<DomainMappingStatus>> {
    let domains = st.domains.lock().await;
    let mut statuses = Vec::with_capacity(domains.mappings.len());
    for handle in domains.mappings.values() {
        statuses.push(domain_status(handle).await);
    }
    statuses.sort_by(|a, b| a.domain.cmp(&b.domain));
    Json(statuses)
}

#[derive(Deserialize)]
struct DomainMappingBody {
    domain: String,
    /// POST defaults to HTTPS; PUT preserves the existing value when omitted.
    #[serde(default)]
    remote_port: Option<u16>,
    #[serde(default)]
    enabled: Option<bool>,
}

fn default_domain_remote_port() -> u16 {
    443
}

fn domain_authority_http(error: DomainAuthorityError) -> (StatusCode, String) {
    let code = match error {
        DomainAuthorityError::NotAdministrator => StatusCode::FORBIDDEN,
        DomainAuthorityError::UnsupportedPlatform => StatusCode::NOT_IMPLEMENTED,
    };
    (code, error.to_string())
}

fn domain_hosts_http(error: HostsError) -> (StatusCode, String) {
    match error {
        HostsError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => (
            StatusCode::FORBIDDEN,
            "无法修改 hosts 文件：当前 PowerMap 进程没有管理员权限".into(),
        ),
        HostsError::Unsupported => (
            StatusCode::NOT_IMPLEMENTED,
            "当前平台不支持受管 hosts 文件".into(),
        ),
        error => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

const MAX_TLS_CLIENT_HELLO_PREFIX: usize = 16 * 1024;
/// Bounds sockets and parser tasks that are waiting for a client to send ClientHello.
const MAX_PENDING_DOMAIN_HANDSHAKES: usize = 64;

fn try_acquire_domain_handshake_slot(limiter: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    limiter.clone().try_acquire_owned().ok()
}

enum TlsClientHelloState {
    Incomplete,
    Sni(String),
}

fn take_tls_slice<'a>(
    data: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], &'static str> {
    let end = cursor.checked_add(len).ok_or("TLS length overflow")?;
    let value = data.get(*cursor..end).ok_or("truncated TLS ClientHello")?;
    *cursor = end;
    Ok(value)
}

/// Extracts SNI from complete TLS handshake records without interpreting or modifying TLS.
/// A ClientHello can span records, so the record payloads are joined only for inspection; the
/// original prefix is retained separately and replayed unchanged into the tunnel.
fn inspect_tls_client_hello(data: &[u8]) -> Result<TlsClientHelloState, &'static str> {
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        if data.len() - cursor < 5 {
            return Ok(TlsClientHelloState::Incomplete);
        }
        if data[cursor] != 22 {
            return Err("expected TLS handshake record");
        }
        let record_len = u16::from_be_bytes([data[cursor + 3], data[cursor + 4]]) as usize;
        if record_len > MAX_TLS_CLIENT_HELLO_PREFIX {
            return Err("TLS record exceeds ClientHello limit");
        }
        let end = cursor + 5 + record_len;
        if end > data.len() {
            return Ok(TlsClientHelloState::Incomplete);
        }
        records.extend_from_slice(&data[cursor + 5..end]);
        if records.len() > MAX_TLS_CLIENT_HELLO_PREFIX {
            return Err("TLS ClientHello exceeds limit");
        }
        if records.len() < 4 {
            cursor = end;
            continue;
        }
        if records[0] != 1 {
            return Err("expected TLS ClientHello");
        }
        let hello_len =
            ((records[1] as usize) << 16) | ((records[2] as usize) << 8) | records[3] as usize;
        if hello_len > MAX_TLS_CLIENT_HELLO_PREFIX - 4 {
            return Err("TLS ClientHello exceeds limit");
        }
        if records.len() < 4 + hello_len {
            cursor = end;
            continue;
        }
        let hello = &records[4..4 + hello_len];
        let mut hello_cursor = 0;
        take_tls_slice(hello, &mut hello_cursor, 2)?; // legacy_version
        take_tls_slice(hello, &mut hello_cursor, 32)?; // random
        let session_len = *take_tls_slice(hello, &mut hello_cursor, 1)?
            .first()
            .ok_or("truncated TLS session id")? as usize;
        take_tls_slice(hello, &mut hello_cursor, session_len)?;
        let cipher_len = u16::from_be_bytes(
            take_tls_slice(hello, &mut hello_cursor, 2)?
                .try_into()
                .map_err(|_| "truncated TLS cipher suites")?,
        ) as usize;
        if cipher_len == 0 || !cipher_len.is_multiple_of(2) {
            return Err("invalid TLS cipher suite list");
        }
        take_tls_slice(hello, &mut hello_cursor, cipher_len)?;
        let compression_len = *take_tls_slice(hello, &mut hello_cursor, 1)?
            .first()
            .ok_or("truncated TLS compression methods")? as usize;
        if compression_len == 0 {
            return Err("invalid TLS compression methods");
        }
        take_tls_slice(hello, &mut hello_cursor, compression_len)?;
        let extensions_len = u16::from_be_bytes(
            take_tls_slice(hello, &mut hello_cursor, 2)?
                .try_into()
                .map_err(|_| "truncated TLS extensions")?,
        ) as usize;
        let extensions = take_tls_slice(hello, &mut hello_cursor, extensions_len)?;
        if hello_cursor != hello.len() {
            return Err("invalid TLS ClientHello trailing bytes");
        }

        let mut extension_cursor = 0;
        while extension_cursor < extensions.len() {
            let extension_type = u16::from_be_bytes(
                take_tls_slice(extensions, &mut extension_cursor, 2)?
                    .try_into()
                    .map_err(|_| "truncated TLS extension type")?,
            );
            let extension_len = u16::from_be_bytes(
                take_tls_slice(extensions, &mut extension_cursor, 2)?
                    .try_into()
                    .map_err(|_| "truncated TLS extension length")?,
            ) as usize;
            let extension = take_tls_slice(extensions, &mut extension_cursor, extension_len)?;
            if extension_type != 0 {
                continue;
            }
            if extension.len() < 2 {
                return Err("truncated TLS SNI extension");
            }
            let names_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
            if names_len != extension.len() - 2 {
                return Err("invalid TLS SNI list length");
            }
            let mut names = 2;
            while names < extension.len() {
                let name_type = extension[names];
                names += 1;
                if names + 2 > extension.len() {
                    return Err("truncated TLS SNI name length");
                }
                let name_len =
                    u16::from_be_bytes([extension[names], extension[names + 1]]) as usize;
                names += 2;
                let name = extension
                    .get(names..names + name_len)
                    .ok_or("truncated TLS SNI name")?;
                names += name_len;
                if name_type != 0 {
                    continue;
                }
                let name = std::str::from_utf8(name).map_err(|_| "TLS SNI is not UTF-8")?;
                let name = name.to_ascii_lowercase();
                config::DomainMapping::new(name.clone())
                    .validate()
                    .map_err(|_| "TLS SNI is not a supported DNS domain")?;
                return Ok(TlsClientHelloState::Sni(name));
            }
            return Err("TLS ClientHello has no hostname SNI");
        }
        return Err("TLS ClientHello has no SNI extension");
    }
    Ok(TlsClientHelloState::Incomplete)
}

#[cfg(test)]
fn parse_tls_client_hello_sni(data: &[u8]) -> Result<String, &'static str> {
    match inspect_tls_client_hello(data)? {
        TlsClientHelloState::Sni(sni) => Ok(sni),
        TlsClientHelloState::Incomplete => Err("truncated TLS ClientHello"),
    }
}

async fn read_tls_client_hello_prefix(local: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut prefix = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = local.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS ClientHello ended early",
            ));
        }
        if prefix.len() + n > MAX_TLS_CLIENT_HELLO_PREFIX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS ClientHello exceeds limit",
            ));
        }
        prefix.extend_from_slice(&chunk[..n]);
        match inspect_tls_client_hello(&prefix) {
            Ok(TlsClientHelloState::Sni(sni)) => return Ok((sni, prefix)),
            Ok(TlsClientHelloState::Incomplete) => {}
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
        }
    }
}

fn disabled_domain_handle(
    mapping: config::DomainMapping,
    hosts_managed: bool,
    last_error: Option<String>,
) -> Arc<DomainMappingHandle> {
    let stats = Stats::with_state(false, true);
    Arc::new(DomainMappingHandle {
        mapping: Arc::new(RwLock::new(mapping)),
        stats,
        hosts_managed: Arc::new(AtomicBool::new(hosts_managed)),
        local_listener: false,
        conn_sem: None,
        last_error: Arc::new(RwLock::new(last_error)),
    })
}

/// Preflight runs through the existing expose TCP path, so DNS and policy are evaluated from
/// the expose network. The opened stream is dropped immediately; TLS bytes are never read.
async fn preflight_domain_mapping(
    link: &Link,
    mapping: &config::DomainMapping,
) -> Result<(), (StatusCode, String)> {
    let request = proto::OpenRequest {
        token: link.token().await,
        host: mapping.domain.clone(),
        port: mapping.remote_port,
        kind: proto::TunnelKind::Tcp,
        register: false,
    };
    match tokio::time::timeout(Duration::from_secs(8), open_with_retry(link, &request)).await {
        Ok(Ok((_send, _recv))) => Ok(()),
        Ok(Err(error)) => Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "无法从 expose 端验证 {}:{}：{}",
                mapping.domain,
                mapping.remote_port,
                diagnostic_reason(&error)
            ),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            format!("验证 {}:{} 超时", mapping.domain, mapping.remote_port),
        )),
    }
}

/// Activates in strict transaction order. Each completed system step is undone when a later
/// step fails, and only the exact PowerMap hosts marker is ever removed.
async fn start_domain_mapping_owned(
    st: &AppState,
    mapping: config::DomainMapping,
) -> Result<Arc<DomainMappingHandle>, (StatusCode, String)> {
    if !mapping.enabled {
        let (hosts_managed, last_error) = match st.hosts.has_loopback(&mapping.domain) {
            Ok(true) => (
                true,
                Some("检测到 PowerMap hosts 条目，等待停用或删除时重试清理".into()),
            ),
            Ok(false) => (false, None),
            Err(error) => (true, Some(format!("无法检查 hosts 清理状态：{error}"))),
        };
        return Ok(disabled_domain_handle(mapping, hosts_managed, last_error));
    }
    mapping
        .validate()
        .map_err(|reason| (StatusCode::BAD_REQUEST, reason))?;
    (st.domain_admin_check)().map_err(domain_authority_http)?;
    (st.domain_preflight)(&mapping).await?;

    let listener_was_started = st.domains.lock().await.listener.is_none();
    if listener_was_started {
        let listener = match (st.domain_listener)().await {
            Ok(listener) => listener,
            Err(error) => {
                return Err((
                    StatusCode::CONFLICT,
                    format!("无法绑定 loopback HTTPS 监听：{error}"),
                ));
            }
        };
        start_shared_domain_listener(st, listener).await;
    }
    if let Err(error) = st.hosts.ensure_loopback(&mapping.domain) {
        stop_shared_domain_listener_if_unused(st).await;
        return Err(domain_hosts_http(error));
    }

    let stats = Stats::new();
    Ok(Arc::new(DomainMappingHandle {
        mapping: Arc::new(RwLock::new(mapping)),
        stats,
        hosts_managed: Arc::new(AtomicBool::new(true)),
        local_listener: true,
        conn_sem: (st.max_conns_per_mapping > 0)
            .then(|| Arc::new(Semaphore::new(st.max_conns_per_mapping))),
        last_error: Arc::new(RwLock::new(None)),
    }))
}

async fn start_shared_domain_listener(st: &AppState, listener: TcpListener) {
    let domains = st.domains.clone();
    let link = st.link.clone();
    let metrics = st.metrics.clone();
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    let handshake_limiter = Arc::new(Semaphore::new(MAX_PENDING_DOMAIN_HANDSHAKES));
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = cancel_task.cancelled() => break,
                result = listener.accept() => result,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    // Reserve before spawning: slow or silent clients cannot accumulate parser
                    // tasks or accepted TCP sockets past this global admission limit.
                    let Some(handshake_permit) =
                        try_acquire_domain_handshake_slot(&handshake_limiter)
                    else {
                        Metrics::inc(&metrics.over_limit);
                        tracing::debug!(peer = %peer, "域名 TLS 握手等待队列已满，拒绝连接");
                        drop(tcp);
                        continue;
                    };
                    let domains = domains.clone();
                    let link = link.clone();
                    let metrics = metrics.clone();
                    let child = cancel_task.child_token();
                    tokio::spawn(async move {
                        let handshake_permit = handshake_permit;
                        let mut tcp = tcp;
                        let (sni, prefix) = match tokio::select! {
                            _ = child.cancelled() => return,
                            result = tokio::time::timeout(Duration::from_secs(5), read_tls_client_hello_prefix(&mut tcp)) => result,
                        } {
                            Ok(Ok(result)) => result,
                            Ok(Err(error)) => {
                                tracing::debug!(error = %error, peer = %peer, "拒绝无效 TLS SNI 连接");
                                return;
                            }
                            Err(_) => return,
                        };
                        // The global permit ends after SNI dispatch. Per-mapping capacity below
                        // remains held for the entire tunnel lifetime.
                        drop(handshake_permit);
                        let handle = { domains.lock().await.mappings.get(&sni).cloned() };
                        let Some(handle) = handle else {
                            tracing::debug!(sni, peer = %peer, "拒绝未映射 TLS SNI");
                            return;
                        };
                        if !handle.local_listener {
                            return;
                        }
                        let permit = match &handle.conn_sem {
                            Some(sem) => match sem.clone().try_acquire_owned() {
                                Ok(permit) => Some(permit),
                                Err(_) => {
                                    Metrics::inc(&metrics.over_limit);
                                    return;
                                }
                            },
                            None => None,
                        };
                        let stats = handle.stats.clone();
                        stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        let (conn_id, conn_meta) = stats.register_conn(peer.to_string());
                        let _active = ActiveGuard {
                            stats: stats.clone(),
                            id: conn_id,
                        };
                        let mapping = handle.mapping.read().await;
                        let request = proto::OpenRequest {
                            token: link.token().await,
                            host: mapping.domain.clone(),
                            port: mapping.remote_port,
                            kind: proto::TunnelKind::Tcp,
                            register: false,
                        };
                        drop(mapping);
                        let _permit = permit;
                        tokio::select! {
                            _ = child.cancelled() => {},
                            result = handle_tunnel(link, request, tcp, stats.clone(), conn_meta, metrics.clone(), prefix) => {
                                if let Err(error) = result {
                                    Metrics::inc(&metrics.tunnels_failed);
                                    stats.record_failure(&error).await;
                                    tracing::warn!(error = %error, sni, "域名隧道关闭");
                                }
                            }
                        }
                    });
                }
                Err(error) => {
                    tracing::error!(error = %error, "共享域名映射本地监听关闭");
                    break;
                }
            }
        }
        let stats = {
            let domains = domains.lock().await;
            domains
                .mappings
                .values()
                .map(|handle| handle.stats.clone())
                .collect::<Vec<_>>()
        };
        for stats in stats {
            stats.mark_listener_stopped().await;
        }
    });
    st.domains.lock().await.listener = Some(SharedDomainListener { task, cancel });
}

async fn stop_shared_domain_listener_if_unused(st: &AppState) {
    let listener = {
        let mut domains = st.domains.lock().await;
        if domains
            .mappings
            .values()
            .any(|handle| handle.local_listener)
        {
            None
        } else {
            domains.listener.take()
        }
    };
    if let Some(listener) = listener {
        listener.cancel.cancel();
        listener.task.abort();
        let _ = listener.task.await;
    }
}

async fn stop_domain_mapping(
    st: &AppState,
    handle: Arc<DomainMappingHandle>,
    remove_hosts: bool,
) -> Result<(), String> {
    let hosts_result = if remove_hosts {
        let domain = handle.mapping.read().await.domain.clone();
        st.hosts
            .remove_loopback(&domain)
            .map_err(|error| domain_hosts_http(error).1)
    } else {
        Ok(())
    };
    stop_shared_domain_listener_if_unused(st).await;
    hosts_result
}

/// Serializes all ownership transitions without retaining attacker-controlled domain keys.
async fn lock_domain_operation(st: &AppState) -> tokio::sync::MutexGuard<'_, ()> {
    st.domain_lifecycle.lock().await
}

async fn record_domain_cleanup_failure(st: &AppState, domain: &str, error: String) {
    let domains = st.domains.lock().await;
    if let Some(handle) = domains.mappings.get(domain) {
        handle.hosts_managed.store(true, Ordering::Relaxed);
        *handle.last_error.write().await = Some(error);
    }
}

async fn create_domain_mapping(
    State(st): State<AppState>,
    Json(body): Json<DomainMappingBody>,
) -> Result<Json<DomainMappingStatus>, (StatusCode, String)> {
    let _operation = lock_domain_operation(&st).await;
    let domains = st.domains.lock().await;
    if domains.mappings.contains_key(&body.domain) {
        return Err((
            StatusCode::CONFLICT,
            format!("{} 已存在域名映射", body.domain),
        ));
    }
    if domains.mappings.len() >= config::domain_mapping_limit(st.max_mappings) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "域名映射数量已达上限 {}",
                config::domain_mapping_limit(st.max_mappings)
            ),
        ));
    }
    drop(domains);
    let mapping = config::DomainMapping {
        domain: body.domain,
        remote_port: body.remote_port.unwrap_or_else(default_domain_remote_port),
        enabled: body.enabled.unwrap_or(true),
    };
    mapping
        .validate()
        .map_err(|reason| (StatusCode::BAD_REQUEST, reason))?;
    let handle = start_domain_mapping_owned(&st, mapping.clone()).await?;
    let status = domain_status(&handle).await;
    let mut domains = st.domains.lock().await;
    if domains.mappings.contains_key(&mapping.domain) {
        drop(domains);
        let _ = stop_domain_mapping(&st, handle, true).await;
        return Err((
            StatusCode::CONFLICT,
            format!("{} 已存在域名映射", mapping.domain),
        ));
    }
    domains.mappings.insert(mapping.domain.clone(), handle);
    drop(domains);
    save_config(&st).await;
    Ok(Json(status))
}

async fn update_domain_mapping(
    State(st): State<AppState>,
    Path(domain): Path<String>,
    Json(body): Json<DomainMappingBody>,
) -> Result<Json<DomainMappingStatus>, (StatusCode, String)> {
    if body.domain != domain {
        return Err((
            StatusCode::BAD_REQUEST,
            "路径与请求体中的 domain 必须一致".into(),
        ));
    }
    let _operation = lock_domain_operation(&st).await;
    let old_handle = {
        let domains = st.domains.lock().await;
        domains
            .mappings
            .get(&domain)
            .ok_or((StatusCode::NOT_FOUND, format!("{domain} 不存在域名映射")))?
            .mapping
            .clone()
    };
    let old_mapping = old_handle.read().await.clone();
    let mapping = config::DomainMapping {
        domain: body.domain,
        remote_port: body.remote_port.unwrap_or(old_mapping.remote_port),
        enabled: body.enabled.unwrap_or(old_mapping.enabled),
    };
    mapping
        .validate()
        .map_err(|reason| (StatusCode::BAD_REQUEST, reason))?;
    if mapping.enabled == old_mapping.enabled {
        // This changes the remote destination without rebuilding the shared loopback socket.
        // Validate it before exposing the new value to future connections or persistence.
        if mapping.enabled && mapping.remote_port != old_mapping.remote_port {
            (st.domain_preflight)(&mapping).await?;
        }
        *old_handle.write().await = mapping;
        let domains = st.domains.lock().await;
        let handle = domains.mappings.get(&domain).expect("域名映射仍存在");
        let status = domain_status(handle).await;
        drop(domains);
        save_config(&st).await;
        return Ok(Json(status));
    }
    let handle = start_domain_mapping_owned(&st, mapping.clone()).await?;
    let enabled = mapping.enabled;
    let old = st
        .domains
        .lock()
        .await
        .mappings
        .insert(domain.clone(), handle);
    if let Some(old) = old
        && let Err(error) = stop_domain_mapping(&st, old, !enabled).await
    {
        tracing::error!(%error, "替换域名映射后清理旧 hosts 条目失败");
        if !enabled {
            record_domain_cleanup_failure(&st, &domain, error).await;
        }
    }
    let status = {
        let domains = st.domains.lock().await;
        domain_status(domains.mappings.get(&domain).expect("域名映射仍存在")).await
    };
    save_config(&st).await;
    Ok(Json(status))
}

async fn toggle_domain_mapping(
    State(st): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<DomainMappingStatus>, (StatusCode, String)> {
    let _operation = lock_domain_operation(&st).await;
    let previous = {
        let domains = st.domains.lock().await;
        domains
            .mappings
            .get(&domain)
            .ok_or((StatusCode::NOT_FOUND, format!("{domain} 不存在域名映射")))?
            .mapping
            .read()
            .await
            .clone()
    };
    let mapping = config::DomainMapping {
        enabled: !previous.enabled,
        ..previous
    };
    let handle = start_domain_mapping_owned(&st, mapping).await?;
    let enabled = handle.mapping.read().await.enabled;
    let old = st
        .domains
        .lock()
        .await
        .mappings
        .insert(domain.clone(), handle);
    if let Some(old) = old
        && let Err(error) = stop_domain_mapping(&st, old, !enabled).await
    {
        tracing::error!(%error, "停用域名映射后清理 hosts 条目失败");
        if !enabled {
            record_domain_cleanup_failure(&st, &domain, error).await;
        }
    }
    let status = {
        let domains = st.domains.lock().await;
        domain_status(domains.mappings.get(&domain).expect("域名映射仍存在")).await
    };
    save_config(&st).await;
    Ok(Json(status))
}

async fn remove_domain_mapping(
    State(st): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let _operation = lock_domain_operation(&st).await;
    let handle = st.domains.lock().await.mappings.remove(&domain);
    match handle {
        Some(handle) => {
            let mut failed_cleanup_mapping = handle.mapping.read().await.clone();
            failed_cleanup_mapping.enabled = false;
            match stop_domain_mapping(&st, handle, true).await {
                Ok(()) => {
                    save_config(&st).await;
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(error) => {
                    // Keep an explicitly disabled record when cleanup failed. Deleting the
                    // persistence first would hide the stale marker and make recovery harder.
                    st.domains.lock().await.mappings.insert(
                        domain.clone(),
                        disabled_domain_handle(failed_cleanup_mapping, true, Some(error.clone())),
                    );
                    save_config(&st).await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("无法清理域名映射 {domain}：{error}"),
                    )
                        .into_response()
                }
            }
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Serialize)]
struct StatItem {
    local: String,
    host: String,
    port: u16,
    /// 是否启用；停用的映射不监听本地端口。
    enabled: bool,
    tx_bytes: u64,
    rx_bytes: u64,
    /// 当前活跃连接数（这条映射上正在透传的隧道数量）。
    active_conns: u64,
    /// 当前活跃连接明细（来源、起始时间、独立字节），供管理页展开查看。
    conns: Vec<ConnSnapshot>,
    /// 传输/代理模式（tcp / udp / http），供管理页给映射打标签。
    mode: &'static str,
    #[serde(flatten)]
    diagnostics: MappingDiagnosticSnapshot,
}

async fn stats(State(st): State<AppState>) -> Json<Vec<StatItem>> {
    let handles: Vec<(Arc<RwLock<config::Mapping>>, Arc<Stats>)> = st
        .inner
        .lock()
        .await
        .mappings
        .values()
        .map(|h| (h.mapping.clone(), h.stats.clone()))
        .collect();
    let mut result = Vec::with_capacity(handles.len());
    for (mapping, stats) in handles {
        let mapping = mapping.read().await;
        result.push(StatItem {
            local: mapping.local.clone(),
            host: mapping.host.clone(),
            port: mapping.port,
            enabled: mapping.enabled,
            tx_bytes: stats.tx.load(Ordering::Relaxed),
            rx_bytes: stats.rx.load(Ordering::Relaxed),
            active_conns: stats.active_conns.load(Ordering::Relaxed),
            conns: stats.conn_snapshot(),
            mode: mapping.mode.as_str(),
            diagnostics: stats.diagnostic_snapshot().await,
        });
    }
    Json(result)
}

/// GET /api/events —— 返回近期控制台事件（最新在前），供“事件”页只读展示。
async fn events(State(st): State<AppState>) -> Json<Vec<Event>> {
    Json(st.events.snapshot())
}

#[derive(Deserialize)]
struct CreateBody {
    local: String,
    host: String,
    port: u16,
    /// 是否启用；创建时省略默认启用，编辑时省略则沿用原状态。
    #[serde(default)]
    enabled: Option<bool>,
    /// 可选的可读名称；省略时按空字符串处理。
    #[serde(default)]
    name: Option<String>,
    /// 传输/代理模式（tcp / udp / http）；省略时创建按 tcp、编辑时沿用原值。
    #[serde(default)]
    mode: Option<config::MappingMode>,
    /// HTTP 网关模式下的按 Host 路由表；仅 http 模式有意义。
    #[serde(default)]
    routes: Option<Vec<config::HttpRoute>>,
}

#[derive(Serialize)]
struct PreflightCheck {
    ok: bool,
    detail: String,
}

#[derive(Serialize)]
struct PreflightResult {
    ready: bool,
    checks: BTreeMap<&'static str, PreflightCheck>,
}

/// POST /api/mappings/preflight --- transiently verifies the same remote path a
/// mapping will use, without creating a listener or persisting configuration.
async fn preflight(
    State(st): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<PreflightResult>, (StatusCode, String)> {
    let mapping = config::Mapping {
        local: body.local,
        host: body.host,
        port: body.port,
        enabled: true,
        name: body.name.unwrap_or_default().trim().to_string(),
        mode: body.mode.unwrap_or_default(),
        routes: body.routes.unwrap_or_default(),
    };
    if let Err(reason) = mapping.validate() {
        return Err((StatusCode::BAD_REQUEST, reason));
    }

    let mut checks = BTreeMap::new();
    // 编辑一条映射而保持本地地址不变时，该地址已被自己的监听占用，属正常情况；
    // 视为可用，不再尝试重绑（否则会误报端口占用）。
    let owned_by_existing = st.inner.lock().await.mappings.contains_key(&mapping.local);
    if owned_by_existing {
        checks.insert(
            "local_listener",
            PreflightCheck {
                ok: true,
                detail: format!("{} 已由现有映射监听", mapping.local),
            },
        );
    } else {
        match TcpListener::bind(&mapping.local).await {
            Ok(listener) => {
                drop(listener);
                checks.insert(
                    "local_listener",
                    PreflightCheck {
                        ok: true,
                        detail: format!("{} 可用于监听", mapping.local),
                    },
                );
            }
            Err(error) => {
                checks.insert(
                    "local_listener",
                    PreflightCheck {
                        ok: false,
                        detail: format!("{} 无法监听: {error}", mapping.local),
                    },
                );
            }
        }
    }

    let configured = st.link.configured().await;
    checks.insert(
        "credential",
        PreflightCheck {
            ok: configured,
            detail: if configured {
                "已配置接入凭证".into()
            } else {
                "尚未配置凭证，请先在“连接”中粘贴 server 凭证".into()
            },
        },
    );

    let local_ready = checks["local_listener"].ok;
    let target = if !local_ready {
        PreflightCheck {
            ok: false,
            detail: "请先解决本地监听地址或端口占用问题".into(),
        }
    } else if !configured {
        PreflightCheck {
            ok: false,
            detail: "需要有效凭证后才能验证目标服务".into(),
        }
    } else {
        // 预检按映射模式选对应隧道类型：udp 校验 UDP 目标可达，其余（含 http 网关）走 tcp。
        let kind = match mapping.mode {
            config::MappingMode::Udp => proto::TunnelKind::Udp,
            _ => proto::TunnelKind::Tcp,
        };
        let request = proto::OpenRequest {
            token: st.link.token().await,
            host: mapping.host.clone(),
            port: mapping.port,
            kind,
            register: false,
        };
        match tokio::time::timeout(Duration::from_secs(8), open_with_retry(&st.link, &request))
            .await
        {
            Ok(Ok((_send, _recv))) => PreflightCheck {
                ok: true,
                detail: format!("{}:{} 可由 server 端访问", mapping.host, mapping.port),
            },
            Ok(Err(error)) => PreflightCheck {
                ok: false,
                detail: diagnostic_reason(&error),
            },
            Err(_) => PreflightCheck {
                ok: false,
                detail: "验证目标服务超时，请检查网络、白名单和目标端口".into(),
            },
        }
    };
    checks.insert("target", target);
    let ready = checks.values().all(|check| check.ok);
    Ok(Json(PreflightResult { ready, checks }))
}

async fn create(
    State(st): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<config::Mapping>, (StatusCode, String)> {
    let mapping = config::Mapping {
        local: body.local,
        host: body.host,
        port: body.port,
        enabled: body.enabled.unwrap_or(true),
        name: body.name.unwrap_or_default().trim().to_string(),
        mode: body.mode.unwrap_or_default(),
        routes: body.routes.unwrap_or_default(),
    };
    if let Err(reason) = mapping.validate() {
        return Err((StatusCode::BAD_REQUEST, reason));
    }
    // 先查上限与重复，再真正绑定端口，避免无谓占用。
    {
        let g = st.inner.lock().await;
        if g.mappings.contains_key(&mapping.local) {
            return Err((
                StatusCode::CONFLICT,
                format!("{} 已存在映射", mapping.local),
            ));
        }
        if st.max_mappings > 0 && g.mappings.len() >= st.max_mappings {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!("映射数量已达上限 {}", st.max_mappings),
            ));
        }
    }
    let handle = start_mapping_owned(&st, mapping.clone()).await?;
    {
        let mut g = st.inner.lock().await;
        // 双检：加锁间隙可能被其他请求抢先插入或触达上限。
        if g.mappings.contains_key(&mapping.local) {
            handle.task.abort();
            handle.cancel.cancel();
            return Err((
                StatusCode::CONFLICT,
                format!("{} 已存在映射", mapping.local),
            ));
        }
        if st.max_mappings > 0 && g.mappings.len() >= st.max_mappings {
            handle.task.abort();
            handle.cancel.cancel();
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!("映射数量已达上限 {}", st.max_mappings),
            ));
        }
        g.mappings.insert(mapping.local.clone(), handle);
    }
    save_config(&st).await;
    st.events.push(
        "info",
        "mapping",
        format!(
            "已创建映射 {} → {}:{}",
            mapping.local, mapping.host, mapping.port
        ),
    );
    Ok(Json(mapping))
}

/// 为停用的映射构造一个不绑定端口、不接受连接的把手：任务只等待取消令牌。
/// 这样启用/停用与增删改共用同一套 MappingHandle 生命周期管理。
fn disabled_handle(mapping: config::Mapping) -> MappingHandle {
    let stats = Stats::with_state(false, true);
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    let task = tokio::spawn(async move {
        cancel_task.cancelled().await;
    });
    MappingHandle {
        mapping: Arc::new(RwLock::new(mapping)),
        task,
        stats,
        cancel,
    }
}

/// 启动一条映射的本地监听；返回运行期把手（含取消令牌）。
/// 停用的映射不绑定本地端口，只登记为 disabled 状态，随时可再启用。
/// 按 mode 分派：tcp / http 走 TCP 监听（http 额外按 Host 头选后端），udp 走 UDP socket。
async fn start_mapping_owned(
    st: &AppState,
    mapping: config::Mapping,
) -> Result<MappingHandle, (StatusCode, String)> {
    if !mapping.enabled {
        return Ok(disabled_handle(mapping));
    }
    match mapping.mode {
        config::MappingMode::Udp => start_udp_mapping(st, mapping).await,
        config::MappingMode::Tcp | config::MappingMode::Http => {
            start_tcp_mapping(st, mapping).await
        }
    }
}

/// 按请求的 Host 头选出该 HTTP 网关映射要拨的后端 (host, port)。
/// 命中具名路由优先；否则用兜底路由（空 host_match）；再否则用映射自身的 host/port。
fn select_http_backend(mapping: &config::Mapping, host_header: Option<&str>) -> (String, u16) {
    // Host 头可能带端口（example.com:8080），比较时只取主机部分并忽略大小写。
    let want = host_header.map(|h| {
        let bare = h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h);
        bare.trim().to_ascii_lowercase()
    });
    if let Some(want) = &want {
        for r in &mapping.routes {
            let m = r.host_match.trim();
            if !m.is_empty() && m.to_ascii_lowercase() == *want {
                return (r.target_host.clone(), r.target_port);
            }
        }
    }
    if let Some(r) = mapping
        .routes
        .iter()
        .find(|r| r.host_match.trim().is_empty())
    {
        return (r.target_host.clone(), r.target_port);
    }
    (mapping.host.clone(), mapping.port)
}

/// 从已读到的 HTTP 请求头字节里解析 Host 头（大小写不敏感）。找不到返回 None。
fn parse_host_header(buf: &[u8]) -> Option<String> {
    // 只在已读到的头部里找；找到 CRLFCRLF 前的 "Host:" 行即可。
    let text = String::from_utf8_lossy(buf);
    for line in text.split("\r\n") {
        if line.is_empty() {
            break; // 头部结束
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("host")
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// 从本地连接窥探 HTTP 请求头，直到读到头结束（CRLFCRLF）或到达上限。
/// 返回 (已读字节, Host 头)。用于 HTTP 网关按 Host 选后端，读走的字节随后重放给后端。
async fn peek_http_head(local: &mut TcpStream) -> std::io::Result<(Vec<u8>, Option<String>)> {
    use tokio::io::AsyncReadExt;
    // 头部窥探上限：足够容纳常见请求头，超过则不再等待，按已读内容决策。
    const MAX_HEAD: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = local.read(&mut chunk).await?;
        if n == 0 {
            break; // 连接在头部结束前关闭
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_HEAD {
            break;
        }
    }
    let host = parse_host_header(&buf);
    Ok((buf, host))
}

/// TCP / HTTP 网关映射：绑定本地 TCP 端口，每个连接复用到 B 的隧道。
/// http 模式下先窥探 Host 头选后端并把读走的头重放给后端；tcp 模式 prefix 为空。
async fn start_tcp_mapping(
    st: &AppState,
    mapping: config::Mapping,
) -> Result<MappingHandle, (StatusCode, String)> {
    let listener = TcpListener::bind(&mapping.local).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("绑定 {} 失败: {e}", mapping.local),
        )
    })?;
    let link = st.link.clone();
    let metrics = st.metrics.clone();
    let local = mapping.local.clone();
    let runtime_mapping = Arc::new(RwLock::new(mapping));
    let mapping_for_task = runtime_mapping.clone();
    let stats = Stats::new();
    let stats_clone = stats.clone();
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    // 单映射并发连接上限（0 = 不限）。
    let conn_sem =
        (st.max_conns_per_mapping > 0).then(|| Arc::new(Semaphore::new(st.max_conns_per_mapping)));

    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                // 映射被删除或进程退出：停止接受新连接并 drain（取消所有子任务）。
                _ = cancel_task.cancelled() => break,
                r = listener.accept() => r,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    // 并发上限：拿不到许可就直接拒绝这条本地连接（丢弃即关闭）。
                    let permit = match &conn_sem {
                        Some(s) => match s.clone().try_acquire_owned() {
                            Ok(p) => Some(p),
                            Err(_) => {
                                Metrics::inc(&metrics.over_limit);
                                tracing::warn!(local = %local, "单映射并发连接达上限，拒绝新连接");
                                drop(tcp);
                                continue;
                            }
                        },
                        None => None,
                    };
                    let link = link.clone();
                    let stats = stats_clone.clone();
                    let stats_for_tunnel = stats.clone();
                    let metrics = metrics.clone();
                    let child = cancel_task.child_token();
                    let mapping = mapping_for_task.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // 持有至隧道结束
                        // 本地连接进入即计入活跃数与明细表，任务结束（含取消/异常）时由 guard 自动移除。
                        stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        let (conn_id, conn_meta) = stats.register_conn(peer.to_string());
                        let _active = ActiveGuard {
                            stats: stats.clone(),
                            id: conn_id,
                        };
                        // 每条隧道建立时实时读取当前令牌，凭证轮换后新连接立即生效。
                        let (mode, host, port, routes) = {
                            let m = mapping.read().await;
                            (m.mode, m.host.clone(), m.port, m.routes.clone())
                        };
                        // HTTP 网关：窥探 Host 头选后端，读走的头随后重放给后端。
                        let mut tcp = tcp;
                        let (target_host, target_port, prefix) = if mode
                            == config::MappingMode::Http
                        {
                            match peek_http_head(&mut tcp).await {
                                Ok((buf, host_header)) => {
                                    let snapshot = config::Mapping {
                                        local: String::new(),
                                        host: host.clone(),
                                        port,
                                        enabled: true,
                                        name: String::new(),
                                        mode,
                                        routes: routes.clone(),
                                    };
                                    let (h, p) =
                                        select_http_backend(&snapshot, host_header.as_deref());
                                    (h, p, buf)
                                }
                                Err(e) => {
                                    Metrics::inc(&metrics.tunnels_failed);
                                    stats
                                        .record_failure(&anyhow::anyhow!("读取 HTTP 头失败: {e}"))
                                        .await;
                                    return;
                                }
                            }
                        } else {
                            (host, port, Vec::new())
                        };
                        let req = proto::OpenRequest {
                            token: link.token().await,
                            host: target_host,
                            port: target_port,
                            kind: proto::TunnelKind::Tcp,
                            register: false,
                        };
                        tokio::select! {
                            _ = child.cancelled() => {}
                            r = handle_tunnel(link.clone(), req, tcp, stats_for_tunnel, conn_meta, metrics.clone(), prefix) => {
                                if let Err(e) = r {
                                    Metrics::inc(&metrics.tunnels_failed);
                                    stats.record_failure(&e).await;
                                    tracing::warn!(error = %e, "隧道关闭");
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!(error = %e, local = %local, "本地监听关闭");
                    break;
                }
            }
        }
        stats_clone.mark_listener_stopped().await;
    });

    Ok(MappingHandle {
        mapping: runtime_mapping,
        task,
        stats,
        cancel,
    })
}

/// UDP 映射：绑定本地 UDP socket，按来源地址维护会话，每个来源复用一条到 B 的 UDP 隧道流。
/// 会话空闲超时后回收；本地无连接语义，因此用来源地址做键。
async fn start_udp_mapping(
    st: &AppState,
    mapping: config::Mapping,
) -> Result<MappingHandle, (StatusCode, String)> {
    let socket = tokio::net::UdpSocket::bind(&mapping.local)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("绑定 UDP {} 失败: {e}", mapping.local),
            )
        })?;
    let socket = Arc::new(socket);
    let link = st.link.clone();
    let metrics = st.metrics.clone();
    let local = mapping.local.clone();
    let max_conns = st.max_conns_per_mapping;
    let runtime_mapping = Arc::new(RwLock::new(mapping));
    let mapping_for_task = runtime_mapping.clone();
    let stats = Stats::new();
    let stats_clone = stats.clone();
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();

    let task = tokio::spawn(async move {
        // 来源地址 → 该会话的上行发送端（把本地收到的数据报喂给会话任务）。
        let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut buf = vec![0u8; proto::MAX_DATAGRAM_LEN as usize];
        loop {
            let recvd = tokio::select! {
                _ = cancel_task.cancelled() => break,
                r = socket.recv_from(&mut buf) => r,
            };
            let (n, peer) = match recvd {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, local = %local, "UDP 本地监听关闭");
                    break;
                }
            };
            let datagram = buf[..n].to_vec();
            // 已有会话：直接投递。发送失败（会话已回收）则移除并新建。
            let existing = {
                let g = sessions.lock().await;
                g.get(&peer).cloned()
            };
            if let Some(tx) = existing
                && tx.send(datagram.clone()).await.is_ok()
            {
                continue;
            }
            // 新会话：并发上限校验（活跃会话数即活跃连接数）。
            if max_conns > 0 && stats_clone.active_conns.load(Ordering::Relaxed) >= max_conns as u64
            {
                Metrics::inc(&metrics.over_limit);
                continue;
            }
            let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
            let _ = tx.send(datagram).await;
            {
                let mut g = sessions.lock().await;
                g.insert(peer, tx);
            }
            let link = link.clone();
            let socket = socket.clone();
            let stats = stats_clone.clone();
            let metrics = metrics.clone();
            let mapping = mapping_for_task.clone();
            let sessions = sessions.clone();
            let child = cancel_task.child_token();
            tokio::spawn(async move {
                stats.active_conns.fetch_add(1, Ordering::Relaxed);
                let (conn_id, conn_meta) = stats.register_conn(peer.to_string());
                let _active = ActiveGuard {
                    stats: stats.clone(),
                    id: conn_id,
                };
                let (host, port) = {
                    let m = mapping.read().await;
                    (m.host.clone(), m.port)
                };
                let req = proto::OpenRequest {
                    token: link.token().await,
                    host,
                    port,
                    kind: proto::TunnelKind::Udp,
                    register: false,
                };
                tokio::select! {
                    _ = child.cancelled() => {}
                    r = handle_udp_session(link.clone(), req, &socket, peer, rx, stats.clone(), conn_meta, metrics.clone()) => {
                        if let Err(e) = r {
                            Metrics::inc(&metrics.tunnels_failed);
                            stats.record_failure(&e).await;
                            tracing::warn!(error = %e, "UDP 隧道关闭");
                        }
                    }
                }
                // 会话结束：从表中移除，让后续同源数据报新建会话。
                sessions.lock().await.remove(&peer);
            });
        }
        stats_clone.mark_listener_stopped().await;
    });

    Ok(MappingHandle {
        mapping: runtime_mapping,
        task,
        stats,
        cancel,
    })
}

/// 一条 UDP 会话：开到 B 的 UDP 隧道流，把本地来源的数据报上行、B 回来的数据报回发本地来源。
/// `rx` 交付本地监听收到的、属于该来源的数据报；空闲超时后结束会话。
#[allow(clippy::too_many_arguments)]
async fn handle_udp_session(
    link: Link,
    req: proto::OpenRequest,
    socket: &Arc<tokio::net::UdpSocket>,
    peer: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<Stats>,
    conn: Arc<ConnMeta>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    // UDP 会话空闲超时：两个方向都静默这么久则回收。
    const IDLE: Duration = Duration::from_secs(60);
    let (mut send, mut recv) = open_with_retry(&link, &req).await?;
    metrics.tunnel_open();
    stats.record_success().await;

    // 上行：本地来源数据报 → QUIC 流（长度前缀）。
    let up = async {
        // 本地端关闭或空闲超时都结束上行；只有拿到数据报才继续。
        while let Ok(Some(datagram)) = tokio::time::timeout(IDLE, rx.recv()).await {
            proto::write_datagram(&mut send, &datagram).await?;
            let n = datagram.len() as u64;
            stats.tx.fetch_add(n, Ordering::Relaxed);
            conn.tx.fetch_add(n, Ordering::Relaxed);
            metrics.bytes_tx.fetch_add(n, Ordering::Relaxed);
        }
        send.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    // 下行：QUIC 流数据报 → 回发本地来源。
    let down = async {
        let mut dbuf = Vec::with_capacity(2048);
        loop {
            match tokio::time::timeout(IDLE, proto::read_datagram(&mut recv, &mut dbuf)).await {
                Ok(Ok(Some(len))) => {
                    socket.send_to(&dbuf[..len], peer).await?;
                    let n = len as u64;
                    stats.rx.fetch_add(n, Ordering::Relaxed);
                    conn.rx.fetch_add(n, Ordering::Relaxed);
                    metrics.bytes_rx.fetch_add(n, Ordering::Relaxed);
                }
                Ok(Ok(None)) | Err(_) => break, // 流结束或空闲超时
                Ok(Err(e)) => return Err(anyhow::Error::from(e)),
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::try_join!(up, down);
    metrics.tunnel_close();
    result.map(|_| ())
}

async fn remove(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.mappings.remove(&id) {
        Some(h) => {
            // 先取消（drain 在途连接：停止 accept + 取消所有子隧道），再 abort 监听任务。
            h.cancel.cancel();
            h.task.abort();
            drop(g);
            save_config(&st).await;
            st.events
                .push("info", "mapping", format!("已断开映射 {id}"));
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}

/// PUT /api/mappings/{id} —— 就地编辑一条映射。
/// 仅改目标（host/port）时复用原监听 socket、不重绑端口，已建立的隧道不受影响，
/// 后续新连接立即用新目标。改本地地址时先绑定新地址再停旧监听，失败则原样保留。
async fn update(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Result<Json<config::Mapping>, (StatusCode, String)> {
    let mut g = st.inner.lock().await;
    let existing = g
        .mappings
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, format!("{id} 不存在映射")))?;
    // 编辑表单不改变启用状态：省略 enabled 时沿用原值，启用/停用走专门的 toggle 接口。
    // name 同理：省略时沿用原名称，避免编辑目标时把名称清空。
    let (was_enabled, was_name, was_mode, was_routes) = {
        let m = existing.mapping.read().await;
        (m.enabled, m.name.clone(), m.mode, m.routes.clone())
    };
    let mapping = config::Mapping {
        local: body.local,
        host: body.host,
        port: body.port,
        enabled: body.enabled.unwrap_or(was_enabled),
        name: body.name.unwrap_or(was_name),
        mode: body.mode.unwrap_or(was_mode),
        routes: body.routes.unwrap_or(was_routes),
    };
    if let Err(reason) = mapping.validate() {
        return Err((StatusCode::BAD_REQUEST, reason));
    }

    // 本地地址与启用状态都没变：复用原把手，原子更新目标，无重绑竞争。
    if mapping.local == id && mapping.enabled == was_enabled {
        let handle = g.mappings.get(&id).expect("已确认存在");
        *handle.mapping.write().await = mapping.clone();
        drop(g);
        save_config(&st).await;
        return Ok(Json(mapping));
    }

    // 改本地地址：新地址不能与其他映射冲突。
    if mapping.local != id && g.mappings.contains_key(&mapping.local) {
        return Err((
            StatusCode::CONFLICT,
            format!("{} 已存在映射", mapping.local),
        ));
    }
    // 先按新参数（含启用态）建把手；成功后再停旧的，避免旧地址提前释放又绑不上新地址。
    let handle = start_mapping_owned(&st, mapping.clone()).await?;
    let old = g.mappings.remove(&id).expect("已确认存在");
    g.mappings.insert(mapping.local.clone(), handle);
    drop(g);
    stop_mapping(old).await;
    save_config(&st).await;
    Ok(Json(mapping))
}

/// POST /api/mappings/{id}/toggle —— 启用/停用一条映射。
/// 停用释放本地端口并 drain 在途连接；启用重新绑定端口。地址不变，仅切换运行态。
async fn toggle(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<config::Mapping>, (StatusCode, String)> {
    let mut g = st.inner.lock().await;
    let existing = g
        .mappings
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, format!("{id} 不存在映射")))?;
    let mut mapping = existing.mapping.read().await.clone();
    mapping.enabled = !mapping.enabled;
    // 启用时按当前地址重新绑定；停用时换成不占端口的把手。任一路径失败则保持原样。
    let handle = start_mapping_owned(&st, mapping.clone()).await?;
    let old = g.mappings.remove(&id).expect("已确认存在");
    g.mappings.insert(mapping.local.clone(), handle);
    drop(g);
    stop_mapping(old).await;
    save_config(&st).await;
    st.events.push(
        "info",
        "mapping",
        format!(
            "已{}映射 {}",
            if mapping.enabled { "启用" } else { "停用" },
            mapping.local
        ),
    );
    Ok(Json(mapping))
}

#[derive(Deserialize)]
struct ToggleAllBody {
    /// 目标启用状态：true 启用全部，false 停用全部。
    enabled: bool,
}

#[derive(Serialize)]
struct ToggleAllResult {
    /// 目标启用状态。
    enabled: bool,
    /// 本次实际切换（状态发生变化）的映射数。
    changed: usize,
    /// 已处于目标状态、无需切换的映射数。
    unchanged: usize,
    /// 尝试启用但绑定本地端口失败、保持原样的映射数。
    failed: usize,
}

/// POST /api/mappings/toggle-all —— 一键启用/停用全部映射。
/// 逐条重建把手：启用时绑定本地端口，停用时释放端口并 drain 在途连接。
/// 某条启用失败（端口被占用等）不影响其余映射，计入 failed 返回。
async fn toggle_all(
    State(st): State<AppState>,
    Json(body): Json<ToggleAllBody>,
) -> Json<ToggleAllResult> {
    let target = body.enabled;
    // 先取出需要切换的 local 列表，避免持锁期间跨 await 重建监听。
    let to_switch: Vec<String> = {
        let g = st.inner.lock().await;
        let mut locals = Vec::new();
        for (local, handle) in g.mappings.iter() {
            if handle.mapping.read().await.enabled != target {
                locals.push(local.clone());
            }
        }
        locals
    };
    let unchanged = st.inner.lock().await.mappings.len() - to_switch.len();
    let mut changed = 0usize;
    let mut failed = 0usize;
    for id in to_switch {
        // 逐条加锁重建：读当前映射、翻转 enabled、建新把手、替换、停旧的。
        let mut g = st.inner.lock().await;
        let Some(existing) = g.mappings.get(&id) else {
            continue; // 中途被删，跳过
        };
        let mut mapping = existing.mapping.read().await.clone();
        if mapping.enabled == target {
            continue; // 已被其他请求切换
        }
        mapping.enabled = target;
        match start_mapping_owned(&st, mapping.clone()).await {
            Ok(handle) => {
                let old = g.mappings.remove(&id).expect("已确认存在");
                g.mappings.insert(mapping.local.clone(), handle);
                drop(g);
                stop_mapping(old).await;
                changed += 1;
            }
            Err(_) => {
                drop(g);
                failed += 1;
            }
        }
    }
    if changed > 0 {
        save_config(&st).await;
        st.events.push(
            "info",
            "mapping",
            format!(
                "已{}全部映射：{} 条{}",
                if target { "启用" } else { "停用" },
                changed,
                if failed > 0 {
                    format!("，{failed} 条失败")
                } else {
                    String::new()
                },
            ),
        );
    }
    Json(ToggleAllResult {
        enabled: target,
        changed,
        unchanged,
        failed,
    })
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/metrics", get(metrics_handler))
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/stats", get(stats))
        .route("/api/events", get(events))
        .route("/api/mappings/preflight", post(preflight))
        .route("/api/mappings", get(list).post(create))
        .route("/api/mappings/{id}", put(update).delete(remove))
        .route("/api/mappings/{id}/toggle", post(toggle))
        .route("/api/mappings/toggle-all", post(toggle_all))
        .route(
            "/api/domain-mappings",
            get(list_domain_mappings).post(create_domain_mapping),
        )
        .route(
            "/api/domain-mappings/{domain}",
            put(update_domain_mapping).delete(remove_domain_mapping),
        )
        .route(
            "/api/domain-mappings/{domain}/toggle",
            post(toggle_domain_mapping),
        )
        .route("/api/node", get(get_node))
        .route("/api/update", get(check_update).post(install_update))
        .route("/api/credential", get(get_credential).post(set_credential))
        .route("/api/reverse", get(get_reverse).put(set_reverse))
        .route("/api/export", get(export_config))
        .route("/api/import", post(import_config))
        .with_state(state)
}

/// GET /api/update —— 查询 GitHub 最新稳定版；只读取元数据，不下载或修改本机文件。
async fn check_update() -> Result<Json<update::UpdateStatus>, (StatusCode, String)> {
    let status = update::cached_update_status(env!("CARGO_PKG_VERSION"))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(status))
}

/// POST /api/update —— 下载、校验并排队安装最新版，随后优雅关闭 HTTP 并 exec 新二进制。
async fn install_update(
    State(st): State<AppState>,
) -> Result<(StatusCode, Json<update::QueuedUpdate>), (StatusCode, String)> {
    let queued = st
        .updater
        .queue_latest()
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    st.events.push(
        "info",
        "update",
        format!(
            "PowerMap v{} 已下载并校验，正在重启安装",
            queued.latest_version
        ),
    );
    st.updater.request_restart();
    Ok((StatusCode::ACCEPTED, Json(queued)))
}

/// GET /api/reverse —— 读取当前反向映射策略（deny-all 语义）。
/// 直接返回运行期的 [`ReverseConfig`]（其 serde 表示即为 API 线格式）。
async fn get_reverse(State(st): State<AppState>) -> Json<ReverseConfig> {
    Json(st.reverse.read().await.clone())
}

/// PUT /api/reverse —— 更新反向映射策略并持久化。校验 CIDR 合法、端口非 0。
/// 开关/白名单变更对后续新反向流即时生效（反向流建立时实时读取策略）。
async fn set_reverse(
    State(st): State<AppState>,
    Json(body): Json<ReverseConfig>,
) -> Result<Json<ReverseConfig>, (StatusCode, String)> {
    // 与 config::AConfig::validate 共用同一套格式校验（空集=拒绝的语义由运行期策略负责）。
    config::validate_allowlist(
        "reverse_allow_networks",
        "reverse_allow_ports",
        &body.allow_networks,
        &body.allow_ports,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    *st.reverse.write().await = body.clone();
    save_config(&st).await;
    st.events.push(
        "info",
        "reverse",
        if body.enabled {
            "已更新反向映射策略（已启用）"
        } else {
            "已关闭反向映射"
        },
    );
    Ok(Json(body))
}

async fn build_config(st: &AppState) -> config::AConfig {
    let mapping_handles: Vec<Arc<RwLock<config::Mapping>>> = st
        .inner
        .lock()
        .await
        .mappings
        .values()
        .map(|h| h.mapping.clone())
        .collect();
    let mut mappings = Vec::with_capacity(mapping_handles.len());
    for mapping in mapping_handles {
        mappings.push(mapping.read().await.clone());
    }
    let mut domain_mappings = Vec::new();
    {
        let domains = st.domains.lock().await;
        domain_mappings.reserve(domains.mappings.len());
        for handle in domains.mappings.values() {
            domain_mappings.push(handle.mapping.read().await.clone());
        }
    }
    domain_mappings.sort_by(|a, b| a.domain.cmp(&b.domain));
    let (node_id, token, published_targets) = {
        let c = st.link.creds.read().await;
        (
            c.node_id.clone(),
            c.token.clone(),
            c.published_targets.clone(),
        )
    };
    let reverse = st.reverse.read().await.clone();
    config::AConfig {
        node_id,
        token,
        web_bind: st.web_bind.clone(),
        web_token: st.web_token.clone(),
        web_tls_cert: st.web_tls_cert.clone(),
        web_tls_key: st.web_tls_key.clone(),
        max_mappings: st.max_mappings,
        max_conns_per_mapping: st.max_conns_per_mapping,
        mappings,
        domain_mappings,
        published_targets,
        reverse_enabled: reverse.enabled,
        reverse_allow_networks: reverse.allow_networks,
        reverse_allow_ports: reverse.allow_ports,
    }
}

async fn save_config(st: &AppState) {
    let cfg = build_config(st).await;
    if let Err(e) = config::save_access(&st.config_path, &cfg) {
        tracing::error!(error = %e, "保存配置失败");
    }
}

/// 解析 node_id 字符串为 PublicKey。
fn parse_target(node_id: &str) -> Result<PublicKey, String> {
    node_id
        .trim()
        .parse::<PublicKey>()
        .map_err(|e| format!("node_id 不是合法的 PublicKey: {e}"))
}

// ---- 凭证 / 导入导出 ----

#[derive(Serialize)]
struct CredentialView {
    configured: bool,
    node_id: String,
    token: String,
    token_hidden: bool,
    published_targets: Vec<config::PublishedTarget>,
}

/// 当前节点的可分享凭证。expose 启动完成前没有凭证时返回 configured=false，
/// 控制台下一次轮询会自动刷新。
#[derive(Serialize)]
struct NodeView {
    configured: bool,
    node_id: String,
    token: String,
    token_hidden: bool,
    credential: Option<tunnel::Credential>,
}

/// GET /api/node —— 读取本机 expose 写出的凭证，供控制台展示和一键复制。
async fn get_node(State(st): State<AppState>) -> Json<NodeView> {
    let path = st.config_path.with_file_name("powermap.credential.json");
    let credential = std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<tunnel::Credential>(&body).ok());
    match credential {
        Some(credential) => Json(NodeView {
            configured: true,
            node_id: credential.node_id.clone(),
            token: credential.token.clone(),
            token_hidden: false,
            credential: Some(credential),
        }),
        None => Json(NodeView {
            configured: false,
            node_id: String::new(),
            token: String::new(),
            token_hidden: false,
            credential: None,
        }),
    }
}

/// GET /api/credential —— 供网页查看/复制当前凭证。
async fn get_credential(State(st): State<AppState>) -> Json<CredentialView> {
    let c = st.link.creds.read().await;
    Json(CredentialView {
        configured: c.target.is_some(),
        node_id: c.node_id.clone(),
        token: c.token.clone(),
        token_hidden: false,
        published_targets: c.published_targets.clone(),
    })
}

/// POST /api/credential —— 粘贴 server 端凭证接入；校验后即时切换连接目标并重连。
async fn set_credential(
    State(st): State<AppState>,
    Json(cred): Json<tunnel::Credential>,
) -> Result<Json<CredentialView>, (StatusCode, String)> {
    if cred.node_id.trim().is_empty() || cred.token.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "node_id 与 token 不能为空".into()));
    }
    let target = parse_target(&cred.node_id).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    st.link
        .set_creds(
            cred.node_id.trim().to_string(),
            cred.token.trim().to_string(),
            target,
            cred.published_targets.clone(),
        )
        .await;
    save_config(&st).await;
    st.events
        .push("info", "credential", "已更新接入凭证，正在用新凭证重连");
    tracing::info!("凭证已更新，将以新凭证重连");
    let c = st.link.creds.read().await;
    Ok(Json(CredentialView {
        configured: true,
        node_id: c.node_id.clone(),
        token: c.token.clone(),
        token_hidden: false,
        published_targets: c.published_targets.clone(),
    }))
}

/// GET /api/export —— 下载完整配置（凭证 + 设置 + 映射）JSON。
async fn export_config(State(st): State<AppState>) -> Response {
    let cfg = build_config(&st).await;
    match serde_json::to_string_pretty(&cfg) {
        Ok(body) => (
            [
                ("content-type", "application/json"),
                (
                    "content-disposition",
                    "attachment; filename=\"powermap.config.json\"",
                ),
            ],
            body,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("序列化失败: {e}"),
        )
            .into_response(),
    }
}

/// 导入模式：覆盖（默认）或合并。
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ImportMode {
    /// 用导入的映射整体替换现有映射（未出现在导入里的映射会被删除）。
    #[default]
    Overwrite,
    /// 把导入的映射叠加到现有映射上：新增缺失的、按 local 更新同名的，不删除现有其他映射。
    Merge,
}

#[derive(Deserialize)]
struct ImportQuery {
    #[serde(default)]
    mode: ImportMode,
}

/// POST /api/import —— 事务式导入配置：应用映射 + 更新凭证 + 存盘。
/// `?mode=overwrite`（默认）整体替换映射；`?mode=merge` 只叠加，不删除现有其他映射。
/// 只接受 AConfig 结构；web_bind/TLS 等监听相关设置不热切换（需重启生效），
/// 这里只应用凭证与映射，避免把 Web 服务在运行中改瘫。
async fn import_config(
    State(st): State<AppState>,
    Query(query): Query<ImportQuery>,
    Json(incoming): Json<config::AConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let merge = query.mode == ImportMode::Merge;
    // 1) 先校验凭证（若带了 node_id）
    let new_target = if incoming.node_id.trim().is_empty() {
        None
    } else {
        Some(parse_target(&incoming.node_id).map_err(|m| (StatusCode::BAD_REQUEST, m))?)
    };
    if incoming.node_id.trim().is_empty() != incoming.token.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "node_id 与 token 必须同时提供或同时留空".into(),
        ));
    }
    // 2) 校验所有映射合法
    let mut locals = HashSet::new();
    for m in &incoming.mappings {
        if let Err(reason) = m.validate() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("映射 {} 非法: {reason}", m.local),
            ));
        }
        if !locals.insert(&m.local) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("本地监听地址 {} 重复", m.local),
            ));
        }
    }

    // 3) 在不触碰现有映射的前提下预启动所有新增监听。相同 local 的监听保持
    // 原 socket，仅在所有新增监听成功后更新其目标，避免重绑同一端口的竞争窗口。
    let mut g = st.inner.lock().await;
    // 上限检查：覆盖模式看导入条数；合并模式看合并后的并集大小（现有 + 导入新增）。
    let merged_total = if merge {
        let added = incoming
            .mappings
            .iter()
            .filter(|m| !g.mappings.contains_key(&m.local))
            .count();
        g.mappings.len() + added
    } else {
        incoming.mappings.len()
    };
    if st.max_mappings > 0 && merged_total > st.max_mappings {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("映射数 {merged_total} 超过上限 {}", st.max_mappings),
        ));
    }
    let mut started_handles = HashMap::new();
    for mapping in &incoming.mappings {
        if g.mappings.contains_key(&mapping.local) {
            continue;
        }
        match start_mapping_owned(&st, mapping.clone()).await {
            Ok(handle) => {
                started_handles.insert(mapping.local.clone(), handle);
            }
            Err(error) => {
                drop(g);
                for (_, handle) in started_handles {
                    stop_mapping(handle).await;
                }
                return Err(error);
            }
        }
    }

    // 全部新监听都已经成功，才一次性替换运行期集合。同地址条目复用监听任务，
    // 所以更新目标时不会因端口仍被旧监听占用而失败。
    let mut previous = std::mem::take(&mut g.mappings);
    let mut next = HashMap::with_capacity(merged_total);
    let mut reused = 0usize;
    for mapping in &incoming.mappings {
        if let Some(handle) = previous.remove(&mapping.local) {
            *handle.mapping.write().await = mapping.clone();
            next.insert(mapping.local.clone(), handle);
            reused += 1;
        } else {
            let handle = started_handles
                .remove(&mapping.local)
                .expect("预启动的监听必须存在");
            next.insert(mapping.local.clone(), handle);
        }
    }
    // 合并模式：保留导入里未提及的现有映射，原样搬进新集合，不停止它们。
    let mut kept = 0usize;
    if merge {
        for (local, handle) in std::mem::take(&mut previous) {
            next.insert(local, handle);
            kept += 1;
        }
    }
    g.mappings = next;
    drop(g);

    // 覆盖模式下被导入删除的映射在新集合提交后才停止，不会影响失败回滚路径。
    // 合并模式下 previous 已被清空，这里不会停止任何映射。
    for (_, handle) in previous {
        stop_mapping(handle).await;
    }

    // 4) 更新凭证（放在映射之后，确保新映射已就绪再触发重连）
    if let Some(target) = new_target {
        st.link
            .set_creds(
                incoming.node_id.trim().to_string(),
                incoming.token.trim().to_string(),
                target,
                incoming.published_targets.clone(),
            )
            .await;
    }
    save_config(&st).await;
    let started = incoming.mappings.len();
    tracing::info!(started, reused, kept, merge, "已导入配置");
    st.events.push(
        "info",
        "mapping",
        format!(
            "已{}配置：{started} 条映射{}",
            if merge { "合并" } else { "导入" },
            if new_target.is_some() {
                "，凭证已更新"
            } else {
                ""
            }
        ),
    );
    Ok(Json(serde_json::json!({
        "started": started,
        "failed": [],
        "reused": reused,
        "kept": kept,
        "merged": merge,
        "credential_updated": new_target.is_some(),
    })))
}

/// 停止一条映射并等待监听 socket 释放，供导入失败回滚和删除的映射复用。
async fn stop_mapping(handle: MappingHandle) {
    handle.cancel.cancel();
    handle.task.abort();
    let _ = handle.task.await;
}

/// 运行接入侧：`cfg` 已由外壳完成凭证/CLI 覆写，这里校验后绑定 iroh endpoint、
/// 恢复映射、起看门狗与反向驱动，并提供 Web 管理页，直到 `cancel` 触发再优雅关停。
pub async fn run(
    cfg: config::AConfig,
    config_path: PathBuf,
    cancel: CancellationToken,
) -> Result<()> {
    cfg.validate().map_err(anyhow::Error::msg)?;

    // 允许无凭证启动：凭证可后续通过 Web 管理页粘贴接入。
    // 若配置里已带 node_id，则解析为连接目标；否则 target 为 None，看门狗不会尝试重连。
    let target: Option<PublicKey> = if cfg.node_id.trim().is_empty() {
        None
    } else {
        Some(
            cfg.node_id
                .trim()
                .parse()
                .context("解析 node_id 失败（应为 PublicKey 字符串）")?,
        )
    };
    if target.is_none() {
        tracing::warn!(
            "尚未配置凭证，client 已启动但暂不连接；请打开 Web 管理页粘贴 server 端凭证。"
        );
    }

    let tls_enabled = !cfg.web_tls_cert.is_empty();

    let is_loopback = cfg
        .web_bind
        .parse::<SocketAddr>()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    if !is_loopback && !tls_enabled {
        tracing::warn!(
            "Web 监听 {} 非回环且未启用 TLS。建议配置 web_tls_cert/web_tls_key 或置于 HTTPS 反代之后。",
            cfg.web_bind
        );
    }

    config::save_access(&config_path, &cfg)?;
    tracing::info!("配置文件: {}", config_path.display());

    let metrics = Metrics::new();
    let events = EventLog::new(200);
    let endpoint = Endpoint::builder(presets::N0)
        .transport_config(tunnel::transport_config())
        .bind()
        .await
        .context("绑定 iroh endpoint 失败")?;
    let link = Link {
        endpoint,
        creds: Arc::new(RwLock::new(Creds {
            node_id: cfg.node_id.clone(),
            token: cfg.token.clone(),
            target,
            published_targets: cfg.published_targets.clone(),
        })),
        conn: Arc::new(Mutex::new(None)),
        connected_since: Arc::new(AtomicU64::new(0)),
    };
    let state = AppState {
        link: link.clone(),
        web_bind: cfg.web_bind.clone(),
        web_token: cfg.web_token.clone(),
        web_tls_cert: cfg.web_tls_cert.clone(),
        web_tls_key: cfg.web_tls_key.clone(),
        max_mappings: cfg.max_mappings,
        max_conns_per_mapping: cfg.max_conns_per_mapping,
        domains: Arc::new(Mutex::new(DomainInner {
            mappings: HashMap::new(),
            listener: None,
        })),
        domain_lifecycle: Arc::new(Mutex::new(())),
        // Unsupported platforms retain ordinary port mappings. Domain operations themselves
        // return a typed unsupported-platform error before this inert path can be used.
        hosts: HostsStore::system()
            .unwrap_or_else(|_| HostsStore::at("/unsupported/powermap-hosts")),
        domain_listener: system_domain_listener(),
        domain_admin_check: Arc::new(current_process_admin),
        domain_preflight: domain_preflight(link.clone()),
        config_path: config_path.clone(),
        metrics: metrics.clone(),
        events: events.clone(),
        inner: Arc::new(Mutex::new(Inner {
            mappings: HashMap::new(),
        })),
        updater: update::UpdateCoordinator::new(cancel.clone()),
        reverse: Arc::new(RwLock::new(ReverseConfig {
            enabled: cfg.reverse_enabled,
            allow_networks: cfg.reverse_allow_networks.clone(),
            allow_ports: cfg.reverse_allow_ports.clone(),
        })),
    };

    // 恢复持久化的映射（受 max_mappings 上限约束）
    let to_restore = cfg.mappings.clone();
    {
        let mut g = state.inner.lock().await;
        for m in to_restore {
            if state.max_mappings > 0 && g.mappings.len() >= state.max_mappings {
                tracing::warn!(local = %m.local, "映射数量已达上限，跳过恢复");
                continue;
            }
            match start_mapping_owned(&state, m.clone()).await {
                Ok(h) => {
                    g.mappings.insert(m.local.clone(), h);
                }
                Err((code, msg)) => {
                    tracing::warn!(%msg, code = %code.as_u16(), "恢复映射失败，跳过")
                }
            }
        }
        tracing::info!("已恢复 {} 条映射", g.mappings.len());
    }

    // Domain mappings restore independently from ordinary port mappings. A failed activation
    // remains visible as disabled with its actionable cause instead of preventing access from
    // starting or silently losing the persisted record.
    for persisted in cfg.domain_mappings.clone() {
        let domain = persisted.domain.clone();
        let handle = match start_domain_mapping_owned(&state, persisted.clone()).await {
            Ok(handle) => handle,
            Err((_, error)) => {
                let hosts_managed = state.hosts.has_loopback(&domain).unwrap_or(false);
                let mut disabled = persisted;
                disabled.enabled = false;
                disabled_domain_handle(disabled, hosts_managed, Some(error))
            }
        };
        state.domains.lock().await.mappings.insert(domain, handle);
    }

    // 看门狗：保持到 B 的热连接，断线（close_reason 置位）时按指数退避主动重连，
    // 避免 B 宕机时疯狂重连打爆
    let watchdog_link = link.clone();
    let watchdog_metrics = metrics.clone();
    let watchdog_events = state.events.clone();
    tokio::spawn(async move {
        let mut failures: u32 = 0;
        // 记录上一轮是否处于断线状态，仅在“断线 → 恢复”跃迁时记一条事件，避免刷屏。
        let mut was_down = false;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // 尚未配置凭证时不尝试连接，静候网页粘贴凭证。
            if !watchdog_link.configured().await {
                failures = 0;
                continue;
            }
            if watchdog_link.is_alive().await {
                failures = 0;
                was_down = false;
                continue;
            }
            if !was_down {
                was_down = true;
                watchdog_events.push("warn", "reconnect", "与 server 的连接断开，看门狗开始重连");
            }
            let delay = tunnel::backoff_delay(
                failures,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            );
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            match watchdog_link.get().await {
                Ok(_) => {
                    failures = 0;
                    was_down = false;
                    Metrics::inc(&watchdog_metrics.reconnects);
                    tracing::info!(?delay, "看门狗：已重连");
                    watchdog_events.push("info", "reconnect", "看门狗已重新连接到 server");
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    tracing::debug!(failures, error = %e, "看门狗重连暂未成功");
                }
            }
        }
    });

    // 反向映射驱动：开启后在到 B 的同一条连接上发一条 register 流（让 B 起内网反向监听），
    // 随后循环 accept_bi 接收 B 发起的反向流，每条按 A 端 deny-all 策略校验后回拨 A 一侧目标。
    // 连接断开则重来；关闭反向时不注册（即便有残留流，策略也会一律拒绝）。
    let reverse_link = link.clone();
    let reverse_state = state.clone();
    let reverse_metrics = metrics.clone();
    tokio::spawn(async move {
        // A 端回拨自己一侧目标的拨号超时，与正向 server 侧保持一致量级。
        const REVERSE_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if !reverse_state.reverse.read().await.enabled {
                continue;
            }
            if !reverse_link.configured().await {
                continue;
            }
            let conn = match reverse_link.get().await {
                Ok(c) => c,
                Err(_) => continue,
            };
            // 在既有连接上开一条 register 流：B 据此认证连接并启动该客户的反向监听。
            let (mut send, mut recv) = match conn.open_bi().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let req = proto::OpenRequest {
                token: reverse_link.token().await,
                host: String::new(),
                port: 0,
                kind: proto::TunnelKind::Tcp,
                register: true,
            };
            if proto::write_open(&mut send, &req).await.is_err() {
                continue;
            }
            match proto::read_status(&mut recv).await {
                Ok(Ok(())) => {
                    reverse_state.events.push(
                        "info",
                        "reverse",
                        "反向映射已注册，开始接受 server 发起的反向连接",
                    );
                    tracing::info!("反向注册成功，开始接受 B 的反向流");
                }
                Ok(Err(msg)) => {
                    // B 未为该客户配置反向监听等：稍等再试，避免忙循环。
                    tracing::debug!(reason = %msg, "B 拒绝反向注册");
                    tokio::time::sleep(Duration::from_secs(20)).await;
                    continue;
                }
                Err(_) => continue,
            }
            // 接受 B 发起的反向流，直到连接断开（accept_bi 出错则回到外层重连并重新注册）。
            while let Ok((s, r)) = conn.accept_bi().await {
                // 每条流实时读取当前策略，运行期开关/白名单变更即时生效。
                let policy = reverse_state.reverse.read().await.policy();
                let metrics = reverse_metrics.clone();
                let events = reverse_state.events.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        tunnel::serve_reverse_stream(s, r, &policy, REVERSE_DIAL_TIMEOUT, &metrics)
                            .await
                    {
                        tracing::debug!(error = %e, "反向流结束");
                        events.push("warn", "reverse", format!("反向连接结束: {e}"));
                    }
                });
            }
        }
    });

    let app = app(state.clone());

    let bind_addr: SocketAddr = cfg
        .web_bind
        .parse()
        .with_context(|| format!("web_bind 不是合法地址: {}", cfg.web_bind))?;
    let scheme = if tls_enabled { "https" } else { "http" };
    tracing::info!("Web 管理页: {}://{}", scheme, cfg.web_bind);

    // 优雅关闭：收到 SIGINT/SIGTERM 后 drain 所有映射的在途隧道，再停止 HTTP。
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        cancel.cancelled().await;
        tracing::info!("收到关闭信号，drain 在途隧道…");
        // 取消所有映射的监听与子隧道
        {
            let g = shutdown_state.inner.lock().await;
            for h in g.mappings.values() {
                h.cancel.cancel();
            }
        }
        {
            let domains = shutdown_state.domains.lock().await;
            if let Some(listener) = &domains.listener {
                listener.cancel.cancel();
            }
        }
        // 给在途连接一点收尾时间，然后优雅停止 HTTP 服务
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    });

    if tls_enabled {
        // 安装进程级默认 crypto provider（ring），axum-server 的 no-provider 变体需要它。
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &cfg.web_tls_cert,
            &cfg.web_tls_key,
        )
        .await
        .context("加载 TLS 证书/私钥失败")?;
        axum_server::bind_rustls(bind_addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        axum_server::bind(bind_addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }
    // A queued update only reaches this point after the HTTP listener has drained. On Unix this
    // replaces the current process image; on a regular shutdown it simply returns false.
    let _ = state.updater.restart_if_queued().await?;
    tracing::info!("已关闭");
    Ok(())
}
