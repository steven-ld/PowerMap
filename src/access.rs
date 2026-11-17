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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post, put};
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;
use crate::{
    config, diagnostic_report,
    diagnostics::{Observation as DiagnosticObservation, Snapshot as DiagnosticSnapshot},
    domain_hosts::{HostsError, HostsStore},
    local_services, mapping_health, port_suggestions, proto, relay_runtime, runtime, tunnel,
    update,
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

/// A peer-owned connection pool. Its mappings share one iroh QUIC connection and reconnect
/// lazily, while credentials stay isolated from every other configured peer.
#[derive(Clone)]
pub struct Link {
    endpoint: Endpoint,
    creds: Arc<RwLock<Creds>>,
    relay: Arc<Mutex<RelayRuntime>>,
    fallback_cancel: CancellationToken,
    conn: Arc<Mutex<Option<Connection>>>,
    /// 当前连接建立时刻（unix 毫秒，0 = 未连接）。每次成功新建连接时刷新，
    /// invalidate 时清零，供管理页展示"已连接时长"。
    connected_since: Arc<AtomicU64>,
}

/// Endpoint 当前生效的 relay 设置及 URL 集合。URL 集合用于热更新时移除旧配置，
/// 让主中继和运行期加入的 iroh 后备集合都能准确替换。
#[derive(Clone)]
struct RelayRuntime {
    settings: config::RelaySettings,
    /// The force-relay policy used to bind this Endpoint. It cannot change in place because iroh
    /// only accepts transport changes while building an Endpoint.
    active_force_relay: bool,
    urls: Vec<RelayUrl>,
    iroh_fallback_enabled: bool,
}

#[derive(Clone, Copy)]
struct RelayApply {
    restart_required: bool,
}

impl RelayRuntime {
    fn new(settings: config::RelaySettings) -> Result<Self, String> {
        let urls = settings.relay_mode()?.relay_map().urls::<Vec<_>>();
        Ok(Self {
            active_force_relay: settings.force_relay,
            settings,
            urls,
            iroh_fallback_enabled: false,
        })
    }
}

impl Link {
    async fn from_peer(
        peer: &config::PeerConfig,
        cancel: CancellationToken,
    ) -> Result<Self, String> {
        let target = match peer.node_id.trim() {
            "" => None,
            node_id => Some(
                node_id
                    .parse::<PublicKey>()
                    .map_err(|_| format!("对端 {} 的 node_id 不是合法的 PublicKey", peer.name))?,
            ),
        };
        let relay_runtime = RelayRuntime::new(peer.relay.clone())?;
        let relay_mode = peer.relay.relay_mode()?;
        let endpoint_builder = Endpoint::builder(presets::N0)
            .relay_mode(relay_mode)
            .transport_config(tunnel::transport_config());
        let endpoint_builder = if peer.relay.force_relay {
            endpoint_builder.clear_ip_transports()
        } else {
            endpoint_builder
        };
        let endpoint = endpoint_builder
            .bind()
            .await
            .map_err(|error| format!("绑定对端 {} 的 iroh endpoint 失败: {error}", peer.name))?;
        let link = Self {
            endpoint,
            creds: Arc::new(RwLock::new(Creds {
                node_id: peer.node_id.clone(),
                token: peer.token.clone(),
                target,
                published_targets: peer.published_targets.clone(),
            })),
            relay: Arc::new(Mutex::new(relay_runtime)),
            fallback_cancel: cancel,
            conn: Arc::new(Mutex::new(None)),
            connected_since: Arc::new(AtomicU64::new(0)),
        };
        link.watch_primary_relay(peer.relay.clone());
        Ok(link)
    }

    async fn apply_peer_config(&self, peer: &config::PeerConfig) -> Result<(), String> {
        let target = match peer.node_id.trim() {
            "" => None,
            node_id => Some(
                node_id
                    .parse::<PublicKey>()
                    .map_err(|_| format!("对端 {} 的 node_id 不是合法的 PublicKey", peer.name))?,
            ),
        };
        let apply = self.set_relay(peer.relay.clone()).await?;
        let creds = Creds {
            node_id: peer.node_id.clone(),
            token: peer.token.clone(),
            target,
            published_targets: peer.published_targets.clone(),
        };
        if apply.restart_required {
            *self.creds.write().await = creds;
        } else {
            self.replace_creds(creds).await;
        }
        Ok(())
    }

    /// 当前接入令牌（每次建隧道时读取，凭证轮换后新连接立即生效）。
    async fn token(&self) -> String {
        self.creds.read().await.token.clone()
    }

    /// 是否已配置凭证（有合法的连接目标）。
    async fn configured(&self) -> bool {
        self.creds.read().await.target.is_some()
    }

    async fn get(&self) -> Result<Connection> {
        if !self.can_open_new_connections().await {
            anyhow::bail!("强制中继设置已变更；重启 PowerMap 后才能建立新连接");
        }
        // 先读凭证再锁连接，与 connected_ips()/transport_path() 的加锁顺序保持一致，
        // 避免两把锁互相等待（ABBA 死锁）。
        let target = self.creds.read().await.target;
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref()
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        let target = target.context("尚未配置凭证：请在 Web 管理页粘贴 server 端的凭证")?;
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
        self.replace_creds(Creds {
            node_id,
            token,
            target: Some(target),
            published_targets,
        })
        .await;
    }

    /// Keep an existing connection alive when a pending force-relay update means the new
    /// credential cannot safely be applied until the Endpoint is rebuilt.
    async fn set_creds_without_reconnect(
        &self,
        node_id: String,
        token: String,
        target: PublicKey,
        published_targets: Vec<config::PublishedTarget>,
    ) {
        *self.creds.write().await = Creds {
            node_id,
            token,
            target: Some(target),
            published_targets,
        };
    }

    /// Replace all credential fields together so a failed persistent update can restore the
    /// previous connection target without leaving a partially updated runtime state.
    async fn replace_creds(&self, creds: Creds) {
        *self.creds.write().await = creds;
        self.invalidate().await;
    }

    async fn relay_settings(&self) -> config::RelaySettings {
        self.relay.lock().await.settings.clone()
    }

    async fn relay_restart_required(&self) -> bool {
        let runtime = self.relay.lock().await;
        runtime.active_force_relay != runtime.settings.force_relay
    }

    async fn can_open_new_connections(&self) -> bool {
        !self.relay_restart_required().await
    }

    /// Monitor the current primary relay set. A changed configuration makes an earlier monitor
    /// inert through its expected-settings comparison before it can add the iroh fallback.
    fn watch_primary_relay(&self, expected: config::RelaySettings) {
        if !expected.uses_official_primary() {
            return;
        }
        let link = self.clone();
        let endpoint = self.endpoint.clone();
        let cancel = self.fallback_cancel.clone();
        tokio::spawn(async move {
            if relay_runtime::wait_for_primary_relay_failure(
                endpoint,
                relay_runtime::PRIMARY_RELAY_GRACE,
                cancel,
            )
            .await
                && link.enable_iroh_fallback(&expected).await
            {
                tracing::warn!("官方中继不可用，已启用 iroh 默认中继后备");
            }
        });
    }

    /// Add the N0 relay map only when the primary configuration has not changed since the
    /// monitor began. iroh's RelayMap is dynamic, so new connections can then fail over without
    /// rebuilding this access endpoint.
    async fn enable_iroh_fallback(&self, expected: &config::RelaySettings) -> bool {
        let fallback = config::iroh_fallback_relay_mode()
            .relay_map()
            .relays::<Vec<_>>();
        let mut runtime = self.relay.lock().await;
        if !expected.uses_official_primary()
            || runtime.settings != *expected
            || runtime.iroh_fallback_enabled
        {
            return false;
        }

        for relay in fallback {
            if !runtime.urls.contains(&relay.url) {
                self.endpoint
                    .insert_relay(relay.url.clone(), relay.clone())
                    .await;
                runtime.urls.push(relay.url.clone());
            }
        }
        runtime.iroh_fallback_enabled = true;
        true
    }

    /// Replace the relay map in place when the Endpoint transport policy is unchanged. A force
    /// relay change is persisted but requires a rebuilt Endpoint, so it deliberately does not
    /// invalidate the current connection.
    async fn set_relay(&self, settings: config::RelaySettings) -> Result<RelayApply, String> {
        let mode = settings.relay_mode()?;
        let map = mode.relay_map();
        let urls = map.urls::<Vec<_>>();
        let configs = map.relays::<Vec<_>>();
        let expected = settings.clone();
        let mut runtime = self.relay.lock().await;

        if runtime.active_force_relay != settings.force_relay {
            runtime.settings = settings;
            return Ok(RelayApply {
                restart_required: true,
            });
        }

        for url in &runtime.urls {
            if !urls.contains(url) {
                self.endpoint.remove_relay(url).await;
            }
        }
        for config in configs {
            self.endpoint.insert_relay(config.url.clone(), config).await;
        }
        runtime.settings = settings;
        runtime.urls = urls;
        runtime.iroh_fallback_enabled = false;
        drop(runtime);

        // Do not close cloned in-flight connections. Removing the cached connection makes
        // subsequent streams establish through the newly selected relay map.
        self.invalidate().await;
        self.watch_primary_relay(expected);
        Ok(RelayApply {
            restart_required: false,
        })
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

#[derive(Clone, Serialize)]
pub struct PeerView {
    id: String,
    name: String,
    configured: bool,
    connected: bool,
    restart_required: bool,
}

#[derive(Default)]
struct PeerRuntime {
    links: HashMap<String, Link>,
    active_references: HashMap<String, usize>,
    watchdogs: HashSet<String>,
}

/// Owns all independently configured remote access peers. Peer endpoints are constructed only
/// when an enabled mapping needs them, and are released when their last active mapping stops.
#[derive(Clone)]
pub struct PeerManager {
    peers: Arc<RwLock<HashMap<String, config::PeerConfig>>>,
    runtime: Arc<Mutex<PeerRuntime>>,
    local_expose_id: Option<PublicKey>,
    cancel: CancellationToken,
}

impl PeerManager {
    fn new(
        peers: impl IntoIterator<Item = config::PeerConfig>,
        cancel: CancellationToken,
        local_expose_id: Option<PublicKey>,
    ) -> Result<Self, String> {
        let mut configured = HashMap::new();
        for peer in peers {
            Self::validate_peer(&peer, local_expose_id)?;
            if configured.insert(peer.id.clone(), peer).is_some() {
                return Err("peer id 重复".into());
            }
        }
        Ok(Self {
            peers: Arc::new(RwLock::new(configured)),
            runtime: Arc::new(Mutex::new(PeerRuntime::default())),
            local_expose_id,
            cancel,
        })
    }

    fn validate_peer(
        peer: &config::PeerConfig,
        local_expose_id: Option<PublicKey>,
    ) -> Result<(), String> {
        peer.validate()?;
        if let (Some(local), false) = (local_expose_id, peer.node_id.trim().is_empty()) {
            let target = peer
                .node_id
                .trim()
                .parse::<PublicKey>()
                .map_err(|_| format!("对端 {} 的 node_id 不是合法的 PublicKey", peer.name))?;
            if target == local {
                return Err(format!(
                    "对端 {} 指向当前 expose 身份；请使用远程节点的 node_id，而不是本机 identity",
                    peer.name
                ));
            }
        }
        Ok(())
    }

    pub async fn get_link(&self, peer_id: &str) -> Result<Link, String> {
        let peer = self
            .peers
            .read()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| format!("映射引用了未知 peer_id {peer_id}"))?;
        let mut runtime = self.runtime.lock().await;
        if let Some(link) = runtime.links.get(peer_id) {
            return Ok(link.clone());
        }
        let link = Link::from_peer(&peer, self.cancel.child_token()).await?;
        runtime.links.insert(peer_id.to_owned(), link.clone());
        Ok(link)
    }

    /// Resolve the one peer that may safely satisfy a request from a pre-peer API.
    /// This only reads the runtime peer model and never constructs an Endpoint.
    async fn legacy_default_peer_id(&self) -> Result<String, String> {
        let peers = self.peers.read().await;
        match peers.values().collect::<Vec<_>>().as_slice() {
            [peer] if peer.name == "默认对端" => Ok(peer.id.clone()),
            _ => Err(
                "当前配置不是单一的“默认对端”；旧版接口无法安全选择对端，请使用对端专用 API".into(),
            ),
        }
    }

    async fn legacy_default_link(&self) -> Result<Link, String> {
        let peer_id = self.legacy_default_peer_id().await?;
        self.get_link(&peer_id).await
    }

    /// Acquire the configured reverse-mapping peer for one registration lifecycle.
    /// A missing owner is accepted only for the one legacy default peer.
    async fn acquire_reverse_link(
        &self,
        configured_peer_id: &str,
    ) -> Result<(String, Link), String> {
        let peer_id = self.resolve_reverse_peer_id(configured_peer_id).await?;
        let link = self.acquire_link(&peer_id).await?;
        Ok((peer_id, link))
    }

    /// Resolve reverse ownership without allocating a peer endpoint.
    async fn resolve_reverse_peer_id(&self, configured_peer_id: &str) -> Result<String, String> {
        if configured_peer_id.trim().is_empty() {
            self.legacy_default_peer_id().await
        } else if self.peers.read().await.contains_key(configured_peer_id) {
            Ok(configured_peer_id.to_owned())
        } else {
            Err(format!(
                "反向映射引用了未知 reverse_peer_id {configured_peer_id}"
            ))
        }
    }

    /// Return a running peer link without starting an inactive peer.
    async fn cached_link(&self, peer_id: &str) -> Result<Option<Link>, String> {
        let peer_id = self.resolve_mapping_peer_id(peer_id).await?;
        Ok(self.runtime.lock().await.links.get(&peer_id).cloned())
    }

    async fn legacy_default_cached_link(&self) -> Result<Option<Link>, String> {
        let peer_id = self.legacy_default_peer_id().await?;
        self.cached_link(&peer_id).await
    }

    /// Return the current peer configuration without allocating an Endpoint. A running peer's
    /// in-memory credential or relay update takes precedence over the persisted value.
    async fn peer_config(&self, peer_id: &str) -> Result<config::PeerConfig, String> {
        let mut peer = self
            .peers
            .read()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| format!("映射引用了未知 peer_id {peer_id}"))?;
        if let Some(link) = self.runtime.lock().await.links.get(peer_id).cloned() {
            let creds = link.creds.read().await;
            peer.node_id = creds.node_id.clone();
            peer.token = creds.token.clone();
            peer.published_targets = creds.published_targets.clone();
            drop(creds);
            peer.relay = link.relay_settings().await;
        }
        Ok(peer)
    }

    async fn legacy_default_peer_config(&self) -> Result<config::PeerConfig, String> {
        let peer_id = self.legacy_default_peer_id().await?;
        self.peer_config(&peer_id).await
    }

    /// Return the immutable owner for a mapping and reject unconfigured peers before any
    /// listener or endpoint is allocated.
    async fn resolve_mapping_peer_id(&self, peer_id: &str) -> Result<String, String> {
        if peer_id.trim().is_empty() {
            return self.legacy_default_peer_id().await;
        }
        if self.peers.read().await.contains_key(peer_id) {
            Ok(peer_id.to_owned())
        } else {
            Err(format!("映射引用了未知 peer_id {peer_id}"))
        }
    }

    async fn acquire_link(&self, peer_id: &str) -> Result<Link, String> {
        let peer = self
            .peers
            .read()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| format!("映射引用了未知 peer_id {peer_id}"))?;
        let mut runtime = self.runtime.lock().await;
        let link = match runtime.links.get(peer_id) {
            Some(link) => link.clone(),
            None => {
                let link = Link::from_peer(&peer, self.cancel.child_token()).await?;
                runtime.links.insert(peer_id.to_owned(), link.clone());
                link
            }
        };
        *runtime
            .active_references
            .entry(peer_id.to_owned())
            .or_default() += 1;
        Ok(link)
    }

    async fn release_link(&self, peer_id: &str) {
        let mut runtime = self.runtime.lock().await;
        let Some(references) = runtime.active_references.get_mut(peer_id) else {
            return;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            runtime.active_references.remove(peer_id);
            runtime.watchdogs.remove(peer_id);
            if let Some(link) = runtime.links.remove(peer_id) {
                link.fallback_cancel.cancel();
            }
        }
    }

    async fn watch_link(
        &self,
        peer_id: String,
        link: Link,
        metrics: Arc<Metrics>,
        events: Arc<EventLog>,
    ) {
        if !self.runtime.lock().await.watchdogs.insert(peer_id.clone()) {
            return;
        }
        let cancel = link.fallback_cancel.clone();
        tokio::spawn(async move {
            let mut failures = 0u32;
            let mut was_down = false;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                if !link.configured().await {
                    failures = 0;
                    continue;
                }
                if link.is_alive().await {
                    failures = 0;
                    was_down = false;
                    continue;
                }
                if !was_down {
                    was_down = true;
                    events.push(
                        "warn",
                        "reconnect",
                        format!("对端 {peer_id} 的连接断开，看门狗开始重连"),
                    );
                }
                let delay = tunnel::backoff_delay(
                    failures,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_nanos())
                        .unwrap_or(0),
                );
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(delay) => {}
                }
                match link.get().await {
                    Ok(_) => {
                        failures = 0;
                        was_down = false;
                        Metrics::inc(&metrics.reconnects);
                    }
                    Err(error) => {
                        failures = failures.saturating_add(1);
                        tracing::debug!(peer_id, failures, error = %error, "看门狗重连暂未成功");
                    }
                }
            }
        });
    }

    pub async fn upsert_peer(&self, peer: config::PeerConfig) -> Result<(), String> {
        Self::validate_peer(&peer, self.local_expose_id)?;
        {
            let peers = self.peers.read().await;
            if peers
                .values()
                .any(|existing| existing.id != peer.id && existing.name.trim() == peer.name.trim())
            {
                return Err(format!("对端名称 {} 重复", peer.name));
            }
        }
        let existing = self.runtime.lock().await.links.get(&peer.id).cloned();
        if let Some(link) = existing {
            link.apply_peer_config(&peer).await?;
        }
        self.peers.write().await.insert(peer.id.clone(), peer);
        Ok(())
    }

    pub async fn remove_peer(&self, peer_id: &str) -> Result<(), String> {
        let mut runtime = self.runtime.lock().await;
        if runtime.active_references.contains_key(peer_id) {
            return Err(format!("对端 {peer_id} 仍被启用映射引用"));
        }
        let link = runtime.links.remove(peer_id);
        drop(runtime);
        if self.peers.write().await.remove(peer_id).is_none() {
            return Err(format!("未知 peer_id {peer_id}"));
        }
        if let Some(link) = link {
            link.fallback_cancel.cancel();
        }
        Ok(())
    }

    pub async fn peer_views(&self) -> Vec<PeerView> {
        let peers = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let links = self.runtime.lock().await.links.clone();
        let mut views = Vec::with_capacity(peers.len());
        for peer in peers {
            let link = links.get(&peer.id);
            views.push(PeerView {
                id: peer.id,
                name: peer.name,
                configured: !peer.node_id.is_empty(),
                connected: match link {
                    Some(link) => link.is_alive().await,
                    None => false,
                },
                restart_required: match link {
                    Some(link) => link.relay_restart_required().await,
                    None => false,
                },
            });
        }
        views.sort_by(|a, b| a.id.cmp(&b.id));
        views
    }

    /// Return one currently live link for aggregate legacy-compatible status surfaces without
    /// allocating an endpoint for a dormant peer. Per-peer state remains available from
    /// `peer_views`; callers use this only for the historical single-path summary fields.
    async fn first_alive_link(&self) -> Option<Link> {
        let links = self
            .runtime
            .lock()
            .await
            .links
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for link in links {
            if link.is_alive().await {
                return Some(link);
            }
        }
        None
    }

    async fn peer_configs(&self) -> Vec<config::PeerConfig> {
        let mut peers = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let links = self.runtime.lock().await.links.clone();
        for peer in &mut peers {
            let Some(link) = links.get(&peer.id) else {
                continue;
            };
            let creds = link.creds.read().await;
            peer.node_id = creds.node_id.clone();
            peer.token = creds.token.clone();
            peer.published_targets = creds.published_targets.clone();
            drop(creds);
            peer.relay = link.relay_settings().await;
        }
        peers.sort_by(|a, b| a.id.cmp(&b.id));
        peers
    }

    /// Atomically replace the configured peer set after validating the full collection. Existing
    /// links are updated in place so listeners which are still draining keep a valid Link. If a
    /// link rejects its new relay configuration, every link changed earlier in this call is
    /// restored from the runtime snapshot.
    async fn replace_peer_configs(
        &self,
        peers: Vec<config::PeerConfig>,
    ) -> Result<Vec<config::PeerConfig>, String> {
        let mut replacement = HashMap::with_capacity(peers.len());
        let mut names = HashSet::with_capacity(peers.len());
        for peer in peers {
            Self::validate_peer(&peer, self.local_expose_id)?;
            if !names.insert(peer.name.trim().to_owned()) {
                return Err(format!("对端名称 {} 重复", peer.name));
            }
            if replacement.insert(peer.id.clone(), peer).is_some() {
                return Err("peer id 重复".into());
            }
        }

        let previous = self.peer_configs().await;
        let previous_by_id = previous
            .iter()
            .map(|peer| (peer.id.clone(), peer.clone()))
            .collect::<HashMap<_, _>>();
        let links = self.runtime.lock().await.links.clone();
        let mut applied = Vec::new();
        for peer in replacement.values() {
            let Some(link) = links.get(&peer.id) else {
                continue;
            };
            if let Err(error) = link.apply_peer_config(peer).await {
                for id in applied {
                    if let (Some(link), Some(previous)) = (links.get(&id), previous_by_id.get(&id))
                        && let Err(rollback_error) = link.apply_peer_config(previous).await
                    {
                        tracing::error!(peer_id = %id, error = %rollback_error, "导入对端失败后无法回滚运行期配置");
                    }
                }
                return Err(error);
            }
            applied.push(peer.id.clone());
        }
        *self.peers.write().await = replacement;

        // Links with no listener reference must not survive a peer replacement indefinitely.
        let stale_links = {
            let peers = self.peers.read().await;
            let mut runtime = self.runtime.lock().await;
            let stale = runtime
                .links
                .keys()
                .filter(|id| {
                    !peers.contains_key(*id) && !runtime.active_references.contains_key(*id)
                })
                .cloned()
                .collect::<Vec<_>>();
            let mut links = Vec::with_capacity(stale.len());
            for id in stale {
                runtime.watchdogs.remove(&id);
                if let Some(link) = runtime.links.remove(&id) {
                    links.push(link);
                }
            }
            links
        };
        for link in stale_links {
            link.fallback_cancel.cancel();
        }
        Ok(previous)
    }

    /// Read the selected default relay without creating an endpoint for an inactive peer.
    async fn legacy_default_relay_settings(&self) -> Result<config::RelaySettings, String> {
        let peer_id = self.legacy_default_peer_id().await?;
        let configured = self
            .peers
            .read()
            .await
            .get(&peer_id)
            .expect("default peer id must remain configured")
            .relay
            .clone();
        match self.runtime.lock().await.links.get(&peer_id).cloned() {
            Some(link) => Ok(link.relay_settings().await),
            None => Ok(configured),
        }
    }

    #[cfg(test)]
    async fn link_count(&self) -> usize {
        self.runtime.lock().await.links.len()
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
    peer_id: Option<String>,
}

struct Inner {
    mappings: HashMap<String, MappingHandle>,
}

type DomainListenerFuture = Pin<Box<dyn Future<Output = io::Result<TcpListener>> + Send>>;
type DomainListenerFactory = Arc<dyn Fn() -> DomainListenerFuture + Send + Sync>;
type MappingListenerFuture = Pin<Box<dyn Future<Output = io::Result<TcpListener>> + Send>>;
type MappingListenerFactory = Arc<dyn Fn(String) -> MappingListenerFuture + Send + Sync>;
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

fn system_mapping_listener() -> MappingListenerFactory {
    Arc::new(|local| Box::pin(async move { TcpListener::bind(local).await }))
}

fn domain_preflight(peers: PeerManager) -> DomainPreflight {
    Arc::new(move |mapping| {
        let peers = peers.clone();
        let mapping = mapping.clone();
        Box::pin(async move {
            let peer_id = peers
                .resolve_mapping_peer_id(&mapping.peer_id)
                .await
                .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
            let link = peers
                .acquire_link(&peer_id)
                .await
                .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
            let result = preflight_domain_mapping(&link, &mapping).await;
            peers.release_link(&peer_id).await;
            result
        })
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
    peer_id: Option<String>,
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
    peers: PeerManager,
    web_bind: String,
    web_token: String,
    web_tls_cert: String,
    web_tls_key: String,
    /// 反向代理域名白名单；用于管理服务的 Host 校验（阻断 DNS rebinding）。
    web_allowed_hosts: Vec<String>,
    max_mappings: usize,
    max_conns_per_mapping: usize,
    domains: Arc<Mutex<DomainInner>>,
    /// Domain resource changes touch shared hosts state and loopback port 443.
    /// A single bounded lock avoids an attacker growing a per-domain lock map indefinitely.
    domain_lifecycle: Arc<Mutex<()>>,
    /// Port mapping changes may replace a listener and need to restore it when persistence
    /// fails. Serialize that full lifecycle rather than only individual hash-map updates.
    mapping_lifecycle: Arc<Mutex<()>>,
    hosts: HostsStore,
    domain_listener: DomainListenerFactory,
    mapping_listener: MappingListenerFactory,
    domain_admin_check: DomainAdminCheck,
    domain_preflight: DomainPreflight,
    config_path: PathBuf,
    metrics: Arc<Metrics>,
    events: Arc<EventLog>,
    inner: Arc<Mutex<Inner>>,
    /// Serializes read-modify-write snapshots of the unified configuration file.
    config_save: Arc<Mutex<()>>,
    /// Keeps relay replacement and its persistence/rollback as one operation.
    relay_update: Arc<Mutex<()>>,
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
    #[serde(default)]
    peer_id: String,
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
    // 对端可能接受流却永不回状态：没有超时的话这条本地连接会永久挂住，
    // 并一直占着映射的并发配额。
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut send, mut recv) = conn.open_bi().await.context("打开隧道流失败")?;
        proto::write_open(&mut send, req).await?;
        match proto::read_status(&mut recv).await? {
            proto::OpenStatus::Ok => {}
            proto::OpenStatus::Error(message) => {
                anyhow::bail!("B 拒绝: {message}");
            }
            proto::OpenStatus::LoopRisk(message) => return Err(LoopRiskError(message).into()),
        }
        let send: Box<dyn AsyncWrite + Unpin + Send> = Box::new(send);
        let recv: Box<dyn AsyncRead + Unpin + Send> = Box::new(recv);
        Ok((send, recv))
    })
    .await
    .map_err(|_| anyhow::anyhow!("隧道握手超时"))?
}

#[derive(Debug)]
struct LoopRiskError(String);

impl std::fmt::Display for LoopRiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B reports an unacknowledged loopback target: {}", self.0)
    }
}

impl std::error::Error for LoopRiskError {}

async fn open_preflight(conn: &Connection, req: &proto::OpenRequest) -> Result<proto::OpenStatus> {
    let (mut send, mut recv) = conn.open_bi().await.context("打开预检流失败")?;
    proto::write_open(&mut send, req).await?;
    Ok(proto::read_status(&mut recv).await?)
}

async fn open_preflight_with_retry(
    link: &Link,
    req: &proto::OpenRequest,
) -> Result<proto::OpenStatus> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..2u8 {
        let conn = match link.get().await {
            Ok(connection) => connection,
            Err(error) => {
                last = Some(error);
                continue;
            }
        };
        match open_preflight(&conn, req).await {
            Ok(status) => return Ok(status),
            Err(error) => {
                link.invalidate().await;
                tracing::warn!(attempt, error = %error, "预检握手失败，重试");
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("无法建立预检流")))
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

async fn powermap_logo() -> impl IntoResponse {
    (
        [("content-type", "image/svg+xml")],
        include_str!("../assets/powermap-logo.svg"),
    )
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
    /// Per-peer state is authoritative in a multi-peer configuration; the legacy fields above
    /// are retained as an aggregate for existing console clients.
    peers: Vec<PeerView>,
}

async fn status(State(st): State<AppState>) -> Json<Status> {
    let n = st.inner.lock().await.mappings.len();
    let peers = st.peers.peer_views().await;
    let configs = st.peers.peer_configs().await;
    let link = st.peers.first_alive_link().await;
    let path_info = match &link {
        Some(link) => link.transport_path().await,
        None => None,
    };
    let m = &st.metrics;
    let (path, rtt_ms, relay) = match path_info {
        Some(p) => (Some(p.path), p.rtt_ms, p.relay),
        None => (None, None, None),
    };
    let connected = link.is_some();
    let connected_since = if connected {
        match link
            .as_ref()
            .expect("connected status requires a selected peer")
            .connected_since
            .load(Ordering::Relaxed)
        {
            0 => None,
            since => Some(since),
        }
    } else {
        None
    };
    let connected_ips = if connected {
        link.as_ref()
            .expect("connected status requires a selected peer")
            .connected_ips()
            .await
    } else {
        Vec::new()
    };
    let configured_peers = configs
        .iter()
        .filter(|peer| !peer.node_id.trim().is_empty())
        .collect::<Vec<_>>();
    let configured = !configured_peers.is_empty();
    let node_id = match configured_peers.as_slice() {
        [peer] => peer.node_id.clone(),
        _ => String::new(),
    };
    Json(Status {
        connected,
        configured,
        node_id,
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
        peers,
    })
}

/// GET /api/diagnostics --- current peer transport and conservative NAT guidance.
async fn diagnostics(State(st): State<AppState>) -> Json<DiagnosticSnapshot> {
    let configured = st
        .peers
        .peer_configs()
        .await
        .iter()
        .any(|peer| !peer.node_id.trim().is_empty());
    let link = st.peers.first_alive_link().await;
    let connected = link.is_some();
    let path_info = match &link {
        Some(link) if connected => link.transport_path().await,
        _ => None,
    };
    let peer_ips = match &link {
        Some(link) if connected => link.connected_ips().await,
        _ => Vec::new(),
    };

    Json(DiagnosticSnapshot::from_observation(
        DiagnosticObservation {
            configured,
            connected,
            path: path_info.as_ref().map(|path| path.path),
            rtt_ms: path_info.as_ref().and_then(|path| path.rtt_ms),
            relay: path_info.and_then(|path| path.relay),
            peer_ips,
        },
    ))
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

/// GET /api/runtime --- read-only local process and service-manager metadata.
async fn runtime_info(State(st): State<AppState>) -> Json<runtime::RuntimeInfo> {
    Json(runtime::snapshot(&st.config_path))
}

/// GET /api/onboarding --- stable first-use state, derived only from local config.
async fn onboarding(State(st): State<AppState>) -> Json<OnboardingStatus> {
    let credential_configured = st
        .peers
        .peer_configs()
        .await
        .iter()
        .any(|peer| !peer.node_id.trim().is_empty());
    let mappings = st.inner.lock().await.mappings.len();
    let domain_mappings = st.domains.lock().await.mappings.len();
    Json(OnboardingStatus {
        credential_configured,
        mappings,
        domain_mappings,
        complete: credential_configured && (mappings > 0 || domain_mappings > 0),
    })
}

#[derive(Serialize)]
struct OnboardingStatus {
    credential_configured: bool,
    mappings: usize,
    domain_mappings: usize,
    complete: bool,
}

/// GET /api/local-services --- fixed local-loopback service candidates only.
async fn local_services() -> Json<Vec<crate::local_services::LocalService>> {
    Json(local_services::discover().await)
}

/// GET /api/mapping-health --- derives a bounded health summary from existing runtime state.
/// It does not create tunnels or probe remote services.
async fn mapping_health(State(st): State<AppState>) -> Json<mapping_health::Summary> {
    let handles: Vec<(Arc<RwLock<config::Mapping>>, Arc<Stats>)> = st
        .inner
        .lock()
        .await
        .mappings
        .values()
        .map(|handle| (handle.mapping.clone(), handle.stats.clone()))
        .collect();
    let mut inputs = Vec::with_capacity(handles.len());
    for (mapping, stats) in handles {
        let mapping = mapping.read().await;
        let diagnostic = stats.diagnostic_snapshot().await;
        inputs.push(mapping_health::MappingInput {
            enabled: mapping.enabled,
            listener_active: diagnostic.listener_active,
            last_tunnel_failed: diagnostic.state == "degraded",
        });
    }
    Json(mapping_health::summarize(inputs))
}

/// GET /api/diagnostic-report --- a downloadable, credential-free support snapshot.
async fn diagnostic_report(State(st): State<AppState>) -> Json<diagnostic_report::Report> {
    let link = st.peers.first_alive_link().await;
    let connected = link.is_some();
    let path = match &link {
        Some(link) if connected => link.transport_path().await,
        _ => None,
    };
    let mappings: Vec<Arc<RwLock<config::Mapping>>> = st
        .inner
        .lock()
        .await
        .mappings
        .values()
        .map(|handle| handle.mapping.clone())
        .collect();
    let mut enabled = 0;
    for mapping in &mappings {
        if mapping.read().await.enabled {
            enabled += 1;
        }
    }
    let events = st
        .events
        .snapshot()
        .into_iter()
        .take(20)
        .map(|event| format!("{}: {}", event.kind, event.message))
        .collect();
    Json(diagnostic_report::build(diagnostic_report::ReportInput {
        version: env!("CARGO_PKG_VERSION").into(),
        transport: diagnostic_report::TransportSummary {
            kind: path
                .as_ref()
                .map_or("disconnected", |path| path.path)
                .into(),
            connected,
            relay: path.as_ref().and_then(|path| path.relay.clone()),
            rtt_ms: path.and_then(|path| path.rtt_ms),
        },
        mappings: diagnostic_report::MappingCounts {
            total: mappings.len(),
            enabled,
            disabled: mappings.len() - enabled,
        },
        recent_events: events,
        generated_at_unix_ms: now_unix_millis(),
    }))
}

#[derive(Deserialize)]
struct PortSuggestionQuery {
    preferred: Option<u16>,
}

/// GET /api/mappings/port-suggestions --- bounded loopback bind checks for local listeners.
async fn port_suggestions(
    Query(query): Query<PortSuggestionQuery>,
) -> Json<Vec<port_suggestions::Suggestion>> {
    let preferred = query.preferred.filter(|port| *port != 0).unwrap_or(8080);
    let upper = preferred.saturating_add(63);
    let occupied: Vec<u16> = (preferred..=upper)
        .filter(|port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, *port)).is_err())
        .collect();
    let suggestions = port_suggestions::suggest_loopback(preferred, &occupied)
        .into_iter()
        .filter(|suggestion| suggestion.port <= upper)
        .collect();
    Json(suggestions)
}

#[derive(Serialize)]
struct MappingTemplate {
    id: &'static str,
    label: &'static str,
    port: u16,
}

/// GET /api/mapping-templates --- static form-fill suggestions, no policy implication.
async fn mapping_templates() -> Json<Vec<MappingTemplate>> {
    Json(vec![
        MappingTemplate {
            id: "ssh",
            label: "SSH",
            port: 22,
        },
        MappingTemplate {
            id: "http",
            label: "HTTP",
            port: 80,
        },
        MappingTemplate {
            id: "https",
            label: "HTTPS",
            port: 443,
        },
        MappingTemplate {
            id: "mysql",
            label: "MySQL",
            port: 3306,
        },
        MappingTemplate {
            id: "postgres",
            label: "PostgreSQL",
            port: 5432,
        },
        MappingTemplate {
            id: "redis",
            label: "Redis",
            port: 6379,
        },
    ])
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use serde_json::Value;
    use tower::ServiceExt;

    static TEST_STATE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct LoopRiskPreflightHandler {
        requests: Arc<Mutex<Vec<proto::OpenRequest>>>,
    }

    impl ProtocolHandler for LoopRiskPreflightHandler {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                let Ok(request) = proto::read_open(&mut recv).await else {
                    continue;
                };
                self.requests.lock().await.push(request.clone());
                let (status, message) = if request.preflight && request.host == "127.0.0.1" {
                    (proto::STATUS_LOOP_RISK, "target resolves to loopback")
                } else {
                    (proto::STATUS_OK, "")
                };
                let _ = proto::write_status(&mut send, status, message).await;
            }
            Ok(())
        }
    }

    async fn configure_loop_risk_preflight(
        state: &AppState,
    ) -> (Router, Arc<Mutex<Vec<proto::OpenRequest>>>) {
        let server = Endpoint::builder(presets::N0).bind().await.unwrap();
        let server_id = server.id();
        let server_addr = server.addr();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let router = Router::builder(server)
            .accept(
                proto::ALPN,
                LoopRiskPreflightHandler {
                    requests: requests.clone(),
                },
            )
            .spawn();
        let link = state.peers.acquire_link("default").await.unwrap();
        let connection = link
            .endpoint
            .connect(server_addr, proto::ALPN)
            .await
            .unwrap();
        *link.conn.lock().await = Some(connection);
        *link.creds.write().await = Creds {
            node_id: server_id.to_string(),
            token: "test-token".into(),
            target: Some(server_id),
            published_targets: Vec::new(),
        };
        (router, requests)
    }

    async fn test_state(web_token: &str) -> AppState {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = format!(
            "{suffix}-{}",
            TEST_STATE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        AppState {
            peers: PeerManager::new(
                [config::PeerConfig {
                    id: "default".into(),
                    name: "默认对端".into(),
                    node_id: String::new(),
                    token: String::new(),
                    published_targets: Vec::new(),
                    relay: config::RelaySettings::default(),
                }],
                CancellationToken::new(),
                None,
            )
            .unwrap(),
            web_bind: "127.0.0.1:0".into(),
            web_token: web_token.into(),
            web_tls_cert: String::new(),
            web_tls_key: String::new(),
            web_allowed_hosts: Vec::new(),
            max_mappings: 8,
            max_conns_per_mapping: 8,
            domains: Arc::new(Mutex::new(DomainInner {
                mappings: HashMap::new(),
                listener: None,
            })),
            domain_lifecycle: Arc::new(Mutex::new(())),
            mapping_lifecycle: Arc::new(Mutex::new(())),
            hosts: {
                let path = std::env::temp_dir().join(format!("powermap-hosts-test-{suffix}"));
                std::fs::write(&path, "").unwrap();
                HostsStore::at(path)
            },
            domain_listener: Arc::new(|| {
                Box::pin(async { TcpListener::bind("127.0.0.1:0").await })
            }),
            mapping_listener: system_mapping_listener(),
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
            config_save: Arc::new(Mutex::new(())),
            relay_update: Arc::new(Mutex::new(())),
            updater: update::UpdateCoordinator::new(CancellationToken::new()),
            reverse: Arc::new(RwLock::new(ReverseConfig::default())),
        }
    }

    async fn test_link(state: &AppState) -> Link {
        state.peers.get_link("default").await.unwrap()
    }

    async fn test_state_with_peers(
        peers: impl IntoIterator<Item = config::PeerConfig>,
    ) -> AppState {
        let state = test_state("").await;
        for peer in peers {
            state.peers.upsert_peer(peer).await.unwrap();
        }
        state
    }

    /// Tests that rewrite the backing config must explicitly mirror that change in the runtime.
    /// A real process initializes its PeerManager from the same loaded configuration.
    async fn replace_test_peers(
        state: &AppState,
        peers: impl IntoIterator<Item = config::PeerConfig>,
    ) {
        for peer in state.peers.peer_configs().await {
            state.peers.remove_peer(&peer.id).await.unwrap();
        }
        for peer in peers {
            state.peers.upsert_peer(peer).await.unwrap();
        }
    }

    #[tokio::test]
    async fn changing_one_peer_does_not_invalidate_another_peer() {
        let state = test_state_with_peers([peer("a", "peer-a"), peer("b", "peer-b")]).await;
        let b = state.peers.get_link("b").await.unwrap();
        let mut updated_a = peer("a", "peer-a");
        updated_a.relay.force_relay = true;

        state.peers.upsert_peer(updated_a).await.unwrap();

        assert!(b.can_open_new_connections().await);
    }

    #[tokio::test]
    async fn peer_links_are_distinct_and_created_lazily() {
        let state = test_state_with_peers([peer("a", "peer-a"), peer("b", "peer-b")]).await;

        assert_eq!(state.peers.link_count().await, 0);
        let a = state.peers.get_link("a").await.unwrap();
        assert_eq!(state.peers.link_count().await, 1);
        let b = state.peers.get_link("b").await.unwrap();

        assert_ne!(a.endpoint.id(), b.endpoint.id());
        assert_eq!(state.peers.link_count().await, 2);
    }

    #[tokio::test]
    async fn legacy_global_reads_reject_multi_peer_configuration() {
        let state = test_state("").await;
        replace_test_peers(&state, [peer("office", "办公室"), peer("home", "家中")]).await;
        let app = app(state);
        let expected = "当前配置不是单一的“默认对端”；旧版接口无法安全选择对端，请使用对端专用 API";

        for path in ["/api/credential", "/api/relay"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CONFLICT, "{path}");
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(std::str::from_utf8(&body).unwrap(), expected, "{path}");
        }
    }

    #[tokio::test]
    async fn reverse_mapping_acquires_its_configured_peer_in_multi_peer_state() {
        let state = test_state_with_peers([peer("office", "office"), peer("home", "home")]).await;
        let reverse = ReverseConfig {
            enabled: true,
            peer_id: "office".into(),
            ..Default::default()
        };

        let (owner_id, link) = state
            .peers
            .acquire_reverse_link(&reverse.peer_id)
            .await
            .unwrap();

        assert_eq!(owner_id, "office");
        assert_eq!(
            link.endpoint.id(),
            state.peers.get_link("office").await.unwrap().endpoint.id()
        );
        assert_eq!(state.peers.link_count().await, 1);
        state.peers.release_link(&owner_id).await;
    }

    #[tokio::test]
    async fn status_does_not_activate_an_inactive_default_peer() {
        let state = test_state("").await;
        let app = app(state.clone());

        let response = app
            .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.peers.link_count().await, 0);
    }

    #[tokio::test]
    async fn aggregate_status_and_onboarding_include_a_configured_nondefault_peer() {
        let remote = Endpoint::builder(presets::N0).bind().await.unwrap();
        let mut office = peer("office", "办公室");
        office.node_id = remote.id().to_string();
        office.token = "office-token".into();
        let state = test_state_with_peers([office]).await;
        let app = app(state);

        let status = response_json(
            app.clone()
                .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status["configured"], true);
        assert!(
            status["peers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|peer| peer["id"] == "office" && peer["configured"] == true)
        );

        let onboarding = response_json(
            app.oneshot(Request::get("/api/onboarding").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(onboarding["credential_configured"], true);
    }

    #[tokio::test]
    async fn mapping_preflight_releases_an_inactive_default_peer() {
        let state = test_state("").await;
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings/preflight")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:0","host":"10.0.0.10","port":443}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.peers.link_count().await, 0);
    }

    #[tokio::test]
    async fn peers_api_creates_and_updates_one_peer_without_changing_another() {
        let state = test_state("").await;
        let app = app(state);

        let first = app
            .clone()
            .oneshot(authenticated_post("/api/peers", r#"{"name":"办公室"}"#))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first = response_json(first).await;
        let first_id = first["id"].as_str().unwrap().to_owned();

        let second = app
            .clone()
            .oneshot(authenticated_post("/api/peers", r#"{"name":"机房"}"#))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second = response_json(second).await;
        let second_id = second["id"].as_str().unwrap().to_owned();

        let updated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/peers/{first_id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"办公室主节点"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);

        let peers = response_json(
            app.oneshot(Request::get("/api/peers").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            peers
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["id"] == first_id)
                .unwrap()["name"],
            "办公室主节点"
        );
        assert_eq!(
            peers
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["id"] == second_id)
                .unwrap()["name"],
            "机房"
        );
    }

    #[tokio::test]
    async fn deleting_referenced_peer_returns_conflict_with_mapping_list() {
        let state = test_state_with_peers([peer("peer-a", "办公室")]).await;
        let mapping = config::Mapping {
            peer_id: "peer-a".into(),
            allow_loopback_target: false,
            local: "127.0.0.1:6379".into(),
            host: "10.0.0.10".into(),
            port: 6379,
            enabled: false,
            name: String::new(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(mapping.local.clone(), disabled_handle(mapping));
        let app = app(state);

        let peers = response_json(
            app.clone()
                .oneshot(Request::get("/api/peers").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(peers[0]["mapping_count"], 1);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/peers/peer-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(response).await["mappings"][0],
            "127.0.0.1:6379"
        );
    }

    #[tokio::test]
    async fn deleting_reverse_mapping_peer_returns_conflict() {
        let state = test_state("").await;
        let app = app(state.clone());

        let configured = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/reverse")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"enabled":true,"peer_id":"default","allow_networks":["10.0.0.0/8"],"allow_ports":[443]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(configured.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/peers/default")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response_json(response).await["reverse_mapping"], true);
        assert!(state.peers.peer_config("default").await.is_ok());
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn mapping_creation_uses_the_requested_peer_id() {
        let state = test_state_with_peers([peer("peer-a", "办公室")]).await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"peer_id":"peer-a","local":"{local}","host":"10.0.0.10","port":6379,"enabled":false}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["peer_id"], "peer-a");
    }

    #[tokio::test]
    async fn offline_peer_requires_acknowledgement_for_a_literal_loopback_mapping() {
        let state = test_state_with_peers([peer("peer-a", "办公室")]).await;
        let app = app(state.clone());
        let body = r#"{"peer_id":"peer-a","local":"127.0.0.1:0","host":"127.0.0.1","port":6379,"enabled":false}"#;

        let rejected = app
            .clone()
            .oneshot(authenticated_post("/api/mappings", body))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert!(state.inner.lock().await.mappings.is_empty());

        let mapped_ipv6 = app
            .clone()
            .oneshot(authenticated_post(
                "/api/mappings",
                r#"{"peer_id":"peer-a","local":"127.0.0.1:0","host":"::ffff:127.0.0.1","port":6379,"enabled":false}"#,
            ))
            .await
            .unwrap();
        assert_eq!(mapped_ipv6.status(), StatusCode::BAD_REQUEST);
        assert!(state.inner.lock().await.mappings.is_empty());

        let acknowledged = app
            .oneshot(authenticated_post(
                "/api/mappings",
                r#"{"peer_id":"peer-a","local":"127.0.0.1:0","host":"127.0.0.1","port":6379,"enabled":false,"acknowledge_loop_risk":true}"#,
            ))
            .await
            .unwrap();
        assert_eq!(acknowledged.status(), StatusCode::OK);
        assert_eq!(
            response_json(acknowledged).await["allow_loopback_target"],
            true
        );
    }

    #[tokio::test]
    async fn import_rejects_unacknowledged_literal_loopback_mappings() {
        let payload = TransferPayload {
            access: config::AConfig {
                peers: vec![default_peer(
                    "default",
                    "",
                    "",
                    config::RelaySettings::default(),
                )],
                mappings: vec![config::Mapping {
                    peer_id: "default".into(),
                    allow_loopback_target: false,
                    local: "127.0.0.1:0".into(),
                    host: "127.0.0.1".into(),
                    port: 6379,
                    enabled: false,
                    name: String::new(),
                    mode: config::MappingMode::Tcp,
                    routes: Vec::new(),
                }],
                ..Default::default()
            },
            relay: None,
        };

        let response = app(test_state("").await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn peer_views_and_removal_do_not_allocate_unused_peer_links() {
        let state = test_state_with_peers([peer("a", "peer-a"), peer("b", "peer-b")]).await;

        let views = state.peers.peer_views().await;
        assert!(
            views
                .iter()
                .any(|view| view.id == "a" && view.name == "peer-a")
        );
        assert!(
            views
                .iter()
                .any(|view| view.id == "b" && !view.configured && !view.connected)
        );
        assert_eq!(state.peers.link_count().await, 0);

        state.peers.remove_peer("b").await.unwrap();
        assert!(
            !state
                .peers
                .peer_views()
                .await
                .iter()
                .any(|view| view.id == "b")
        );
        assert_eq!(state.peers.link_count().await, 0);
    }

    #[tokio::test]
    async fn disabled_mapping_does_not_allocate_its_peer_link() {
        let state = test_state_with_peers([peer("inactive", "inactive")]).await;
        let mapping = config::Mapping {
            peer_id: "inactive".into(),
            allow_loopback_target: false,
            local: "127.0.0.1:0".into(),
            host: "127.0.0.1".into(),
            port: 8080,
            enabled: false,
            name: String::new(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };

        let _handle = start_mapping_owned(&state, mapping).await.unwrap();

        assert_eq!(state.peers.link_count().await, 0);
    }

    #[tokio::test]
    async fn enabled_mapping_rejects_unknown_peer_before_allocating_a_link() {
        let state = test_state_with_peers([peer("known", "known")]).await;
        let mapping = config::Mapping {
            peer_id: "missing".into(),
            allow_loopback_target: false,
            local: "127.0.0.1:0".into(),
            host: "127.0.0.1".into(),
            port: 8080,
            enabled: true,
            name: String::new(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };

        let error = match start_mapping_owned(&state, mapping).await {
            Err((_, error)) => error,
            Ok(_) => panic!("unknown peer mapping must not start"),
        };

        assert!(error.contains("未知 peer_id missing"));
        assert_eq!(state.peers.link_count().await, 0);
    }

    #[tokio::test]
    async fn changing_mapping_peer_rebuilds_its_listener_handle() {
        let state = test_state_with_peers([peer("a", "peer-a"), peer("b", "peer-b")]).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap().to_string();
        drop(listener);
        let old_mapping = config::Mapping {
            peer_id: "a".into(),
            allow_loopback_target: false,
            local: local.clone(),
            host: "127.0.0.1".into(),
            port: 8080,
            enabled: true,
            name: String::new(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        let old = start_mapping_owned(&state, old_mapping).await.unwrap();
        let old_task = old.task.id();
        let updated = config::Mapping {
            peer_id: "b".into(),
            ..old.mapping.read().await.clone()
        };

        let rebuilt = rebuild_mapping_for_peer(&state, old, updated)
            .await
            .unwrap();

        assert_ne!(old_task, rebuilt.task.id());
        assert_eq!(rebuilt.peer_id.as_deref(), Some("b"));
        stop_mapping(&state, rebuilt).await;
    }

    #[tokio::test]
    async fn self_peer_identity_is_rejected() {
        let local = Endpoint::builder(presets::N0).bind().await.unwrap().id();
        let manager = PeerManager::new([], CancellationToken::new(), Some(local)).unwrap();
        let mut self_peer = peer("self", "self");
        self_peer.node_id = local.to_string();
        self_peer.token = "token".into();

        let error = manager.upsert_peer(self_peer).await.unwrap_err();

        assert!(error.contains("当前 expose 身份"));
    }

    #[tokio::test]
    async fn save_config_preserves_loaded_domain_mappings() {
        let state = test_state("").await;
        let domain_mappings = [config::DomainMapping::new("ai-router.dl-aiot.com")];
        state.domains.lock().await.mappings.insert(
            domain_mappings[0].domain.clone(),
            disabled_domain_handle(domain_mappings[0].clone(), false, None),
        );

        persist_config(&state).await.unwrap();

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(saved.domain_mappings.len(), 1);
        assert_eq!(saved.domain_mappings[0].domain, domain_mappings[0].domain);
        assert_eq!(saved.domain_mappings[0].peer_id, saved.peers[0].id);
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn save_config_preserves_existing_peer_model() {
        let state = test_state("").await;
        let mapping = config::Mapping {
            peer_id: "peer-b".into(),
            allow_loopback_target: true,
            local: "127.0.0.1:0".into(),
            host: "10.0.0.8".into(),
            port: 8080,
            enabled: false,
            name: "application".into(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(mapping.local.clone(), disabled_handle(mapping.clone()));
        let peers = vec![
            config::PeerConfig {
                id: "peer-a".into(),
                name: "office".into(),
                node_id: "node-a".into(),
                token: "token-a".into(),
                published_targets: vec![config::PublishedTarget {
                    host: "10.0.0.10".into(),
                    port: 443,
                    label: "HTTPS".into(),
                }],
                relay: config::RelaySettings::default(),
            },
            config::PeerConfig {
                id: "peer-b".into(),
                name: "home".into(),
                node_id: "node-b".into(),
                token: "token-b".into(),
                published_targets: Vec::new(),
                relay: config::RelaySettings {
                    relays: vec![config::RelayEntry {
                        url: "https://relay.example.test".into(),
                        auth_token: "relay-token".into(),
                    }],
                    force_relay: true,
                },
            },
        ];
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: peers.clone(),
                    mappings: vec![mapping.clone()],
                    ..Default::default()
                }),
            },
        )
        .unwrap();

        replace_test_peers(&state, peers.clone()).await;

        persist_config(&state).await.unwrap();

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(saved.peers, peers);
        assert_eq!(saved.mappings, vec![mapping]);
        std::fs::remove_file(&state.config_path).unwrap();
    }

    fn relay_settings(url: &str, auth_token: &str) -> config::RelaySettings {
        config::RelaySettings {
            relays: vec![config::RelayEntry {
                url: url.into(),
                auth_token: auth_token.into(),
            }],
            force_relay: false,
        }
    }

    fn default_peer(
        id: &str,
        node_id: &str,
        token: &str,
        relay: config::RelaySettings,
    ) -> config::PeerConfig {
        config::PeerConfig {
            id: id.into(),
            name: "默认对端".into(),
            node_id: node_id.into(),
            token: token.into(),
            published_targets: Vec::new(),
            relay,
        }
    }

    fn peer(id: &str, name: &str) -> config::PeerConfig {
        config::PeerConfig {
            id: id.into(),
            name: name.into(),
            node_id: String::new(),
            token: String::new(),
            published_targets: Vec::new(),
            relay: config::RelaySettings::default(),
        }
    }

    #[test]
    fn legacy_bridge_updates_only_the_default_peer_and_serializes_peer_credentials() {
        let runtime = config::AConfig {
            node_id: "new-node".into(),
            token: "new-token".into(),
            published_targets: vec![config::PublishedTarget {
                host: "10.0.0.10".into(),
                port: 443,
                label: "HTTPS".into(),
            }],
            ..Default::default()
        };
        let persisted = config::AConfig {
            peers: vec![default_peer(
                "legacy-default",
                "old-node",
                "old-token",
                relay_settings("https://old-relay.example.test", "old-relay-token"),
            )],
            ..Default::default()
        };

        let relay_only = merge_legacy_runtime_access(
            runtime.clone(),
            Some(&persisted),
            &relay_settings("https://new-relay.example.test", "new-relay-token"),
            LegacyRuntimeSync::RELAY,
        );
        assert_eq!(relay_only.peers[0].token, "old-token");
        assert_eq!(
            relay_only.peers[0].relay.relays[0].auth_token,
            "new-relay-token"
        );

        let merged = merge_legacy_runtime_access(
            runtime,
            Some(&persisted),
            &relay_settings("https://new-relay.example.test", "new-relay-token"),
            LegacyRuntimeSync {
                credentials: true,
                relay: true,
            },
        );

        assert!(merged.node_id.is_empty());
        assert!(merged.token.is_empty());
        assert_eq!(merged.peers.len(), 1);
        assert_eq!(merged.peers[0].node_id, "new-node");
        assert_eq!(merged.peers[0].token, "new-token");
        assert_eq!(
            merged.peers[0].relay.relays[0].auth_token,
            "new-relay-token"
        );
        let serialized = serde_json::to_value(&merged).unwrap();
        assert!(serialized.get("token").is_none());
        assert_eq!(serialized["peers"][0]["token"], "new-token");

        let redacted = merged.redacted_for_export();
        let redacted = serde_json::to_value(redacted).unwrap();
        assert_eq!(redacted["peers"][0]["token"], "");
        assert!(
            redacted["peers"][0]["relay"]["relays"][0]
                .get("auth_token")
                .is_none()
        );

        let mut config = config::Config {
            relay: relay_settings("https://expose-relay.example.test", "expose-relay-token"),
            expose: Some(config::BConfig::default()),
            access: Some(merged),
        };
        config.normalize_access_peers().unwrap();
        assert_eq!(config.relay.relays[0].auth_token, "expose-relay-token");
    }

    #[test]
    fn legacy_bridge_allows_only_the_migrated_default_peer() {
        let default = config::AConfig {
            peers: vec![default_peer(
                "legacy-default",
                "node",
                "token",
                config::RelaySettings::default(),
            )],
            ..Default::default()
        };
        assert_eq!(
            legacy_default_peer_for_route(Some(&default)).unwrap(),
            Some("legacy-default".into())
        );

        let multi_peer = config::AConfig {
            peers: vec![peer("office", "office"), peer("home", "home")],
            ..Default::default()
        };
        assert!(legacy_default_peer_for_route(Some(&multi_peer)).is_err());
    }

    #[test]
    fn legacy_bridge_preserves_default_peer_without_an_explicit_runtime_update() {
        let runtime = config::AConfig {
            node_id: "runtime-node".into(),
            token: "runtime-token".into(),
            ..Default::default()
        };
        let persisted = config::AConfig {
            peers: vec![default_peer(
                "legacy-default",
                "stored-node",
                "stored-token",
                relay_settings("https://stored-relay.example.test", "stored-relay-token"),
            )],
            ..Default::default()
        };

        let merged = merge_legacy_runtime_access(
            runtime,
            Some(&persisted),
            &relay_settings("https://runtime-relay.example.test", "runtime-relay-token"),
            LegacyRuntimeSync::NONE,
        );

        assert_eq!(merged.peers[0].node_id, "stored-node");
        assert_eq!(merged.peers[0].token, "stored-token");
        assert_eq!(
            merged.peers[0].relay.relays[0].auth_token,
            "stored-relay-token"
        );
    }

    #[test]
    fn peer_aware_import_accepts_complete_peer_collection_and_legacy_shape() {
        let multi_peer = config::AConfig {
            peers: vec![peer("office", "office"), peer("home", "home")],
            ..Default::default()
        };
        let imported = normalize_imported_access(multi_peer, None).unwrap();
        assert_eq!(imported.peers.len(), 2);
        assert!(imported.peer("office").is_some());
        assert!(imported.peer("home").is_some());

        let legacy = config::AConfig {
            node_id: String::new(),
            token: String::new(),
            mappings: vec![config::Mapping {
                peer_id: String::new(),
                allow_loopback_target: false,
                local: "127.0.0.1:0".into(),
                host: "10.0.0.10".into(),
                port: 443,
                enabled: false,
                name: "HTTPS".into(),
                mode: config::MappingMode::Tcp,
                routes: Vec::new(),
            }],
            ..Default::default()
        };
        let imported = normalize_imported_access(legacy, None).unwrap();
        assert_eq!(imported.peers.len(), 1);
        assert_eq!(imported.peers[0].name, "默认对端");
        assert_eq!(imported.mappings[0].peer_id, imported.peers[0].id);
    }

    #[tokio::test]
    async fn import_persists_the_reverse_peer_owner() {
        let state = test_state("").await;
        let payload = TransferPayload {
            access: config::AConfig {
                peers: vec![default_peer(
                    "office",
                    "",
                    "",
                    config::RelaySettings::default(),
                )],
                reverse_enabled: true,
                reverse_peer_id: "office".into(),
                reverse_allow_networks: vec!["10.0.0.0/8".into()],
                reverse_allow_ports: vec![443],
                ..Default::default()
            },
            relay: None,
        };
        let app = app(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let reverse = response_json(
            app.oneshot(Request::get("/api/reverse").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(reverse["enabled"], true);
        assert_eq!(reverse["peer_id"], "office");

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config;
        let saved_access = saved.access.unwrap();
        assert!(saved_access.reverse_enabled);
        assert_eq!(saved_access.reverse_peer_id, "office");
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn merge_import_without_reverse_fields_preserves_active_reverse_mapping() {
        let state = test_state("").await;
        let app = app(state.clone());

        let configured = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/reverse")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"enabled":true,"peer_id":"default","allow_networks":["10.0.0.0/8"],"allow_ports":[443]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(configured.status(), StatusCode::OK);

        let imported = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import?mode=merge")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "mappings": [{
                                "local": "127.0.0.1:0",
                                "host": "10.0.0.8",
                                "port": 443,
                                "enabled": false,
                            }],
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imported.status(), StatusCode::OK);

        let reverse = response_json(
            app.oneshot(Request::get("/api/reverse").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(reverse["enabled"], true);
        assert_eq!(reverse["peer_id"], "default");

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert!(saved.reverse_enabled);
        assert_eq!(saved.reverse_peer_id, "default");
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[test]
    fn legacy_reverse_import_migrates_to_the_generated_default_peer() {
        let legacy = config::AConfig {
            reverse_enabled: true,
            ..Default::default()
        };

        let imported = normalize_imported_access(legacy, None).unwrap();

        assert_eq!(imported.peers.len(), 1);
        assert_eq!(imported.peers[0].name, "默认对端");
        assert_eq!(imported.reverse_peer_id, imported.peers[0].id);
    }

    #[tokio::test]
    async fn credential_update_persists_to_the_default_peer_without_overwriting_expose_relay() {
        let state = test_state("").await;
        let expose_relay =
            relay_settings("https://expose-relay.example.test", "expose-relay-token");
        config::save(
            &state.config_path,
            &config::Config {
                relay: expose_relay.clone(),
                expose: Some(config::BConfig::default()),
                access: Some(config::AConfig {
                    peers: vec![default_peer(
                        "legacy-default",
                        "old-node",
                        "old-token",
                        relay_settings("https://old-access-relay.example.test", "old-access-token"),
                    )],
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        let node_id = test_link(&state).await.endpoint.id().to_string();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"node_id":"{node_id}","token":"new-access-token","published_targets":[{{"host":"10.0.0.10","port":443,"label":"HTTPS"}}],"relay":{{"relays":[{{"url":"https://access-relay.example.test","auth_token":"access-relay-token"}}],"force_relay":false}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config;
        let access = saved.access.unwrap();
        let peer = access
            .legacy_default_peer_id()
            .and_then(|id| access.peer(id))
            .unwrap();
        assert_eq!(peer.node_id, node_id);
        assert_eq!(peer.token, "new-access-token");
        assert_eq!(peer.published_targets[0].host, "10.0.0.10");
        assert_eq!(
            peer.relay.relays[0].url,
            "https://access-relay.example.test"
        );
        assert_eq!(peer.relay.relays[0].auth_token, "access-relay-token");
        assert_eq!(saved.relay, expose_relay);
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn legacy_credential_route_rejects_a_multi_peer_configuration() {
        let state = test_state("").await;
        let peers = vec![peer("office", "office"), peer("home", "home")];
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: peers.clone(),
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        let node_id = test_link(&state).await.endpoint.id().to_string();
        replace_test_peers(&state, peers).await;
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"node_id":"{node_id}","token":"new-access-token"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(state.peers.get_link("default").await.is_err());
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn peer_aware_export_includes_credentials_only_when_requested() {
        let state = test_state("").await;
        let export_node_id = test_link(&state).await.endpoint.id().to_string();
        let mapping = config::Mapping {
            peer_id: "legacy-default".into(),
            allow_loopback_target: false,
            local: "127.0.0.1:0".into(),
            host: "10.0.0.10".into(),
            port: 443,
            enabled: false,
            name: "HTTPS".into(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        let domain_mapping = config::DomainMapping {
            peer_id: "legacy-default".into(),
            allow_loopback_target: false,
            domain: "export.example.test".into(),
            remote_port: 8443,
            enabled: false,
        };
        let mut export_peer = default_peer(
            "legacy-default",
            &export_node_id,
            "export-access-token",
            relay_settings(
                "https://export-access-relay.example.test",
                "export-access-relay-token",
            ),
        );
        export_peer.published_targets = vec![config::PublishedTarget {
            host: "10.0.0.10".into(),
            port: 443,
            label: "HTTPS".into(),
        }];
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(mapping.local.clone(), disabled_handle(mapping.clone()));
        state.domains.lock().await.mappings.insert(
            domain_mapping.domain.clone(),
            disabled_domain_handle(domain_mapping.clone(), false, None),
        );
        config::save(
            &state.config_path,
            &config::Config {
                relay: relay_settings("https://expose-relay.example.test", "expose-relay-token"),
                expose: Some(config::BConfig::default()),
                access: Some(config::AConfig {
                    peers: vec![export_peer.clone()],
                    mappings: vec![mapping],
                    domain_mappings: vec![domain_mapping],
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        replace_test_peers(&state, [export_peer.clone()]).await;
        let source_app = app(state.clone());

        let redacted = response_json(
            source_app
                .clone()
                .oneshot(Request::get("/api/export").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(redacted["peers"][0]["id"], "legacy-default");
        assert_eq!(redacted["peers"][0]["token"], "");
        assert!(
            redacted["peers"][0]["relay"]["relays"][0]
                .get("auth_token")
                .is_none()
        );

        let full = response_json(
            source_app
                .oneshot(
                    Request::get("/api/export?include_credentials=true")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(full.get("token").is_none());
        assert_eq!(full["peers"][0]["node_id"], export_node_id);
        assert_eq!(full["peers"][0]["token"], "export-access-token");
        assert_eq!(
            full["peers"][0]["published_targets"][0]["host"],
            "10.0.0.10"
        );
        assert_eq!(
            full["peers"][0]["relay"]["relays"][0]["auth_token"],
            "export-access-relay-token"
        );
        assert_eq!(full["mappings"][0]["peer_id"], "legacy-default");
        assert_eq!(full["domain_mappings"][0]["peer_id"], "legacy-default");

        let restored = test_state("").await;
        replace_test_peers(&restored, [export_peer]).await;
        let restored_app = app(restored.clone());
        let imported = restored_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&full).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imported.status(), StatusCode::OK);
        let restored_config = config::load_config(&restored.config_path, None)
            .unwrap()
            .config;
        let restored_access = restored_config.access.unwrap();
        assert_eq!(restored_access.peers[0].id, "legacy-default");
        assert_eq!(restored_access.peers[0].token, "export-access-token");
        assert_eq!(
            restored_access.peers[0].relay.relays[0].auth_token,
            "export-access-relay-token"
        );
        assert_eq!(restored_access.mappings[0].peer_id, "legacy-default");
        assert_eq!(
            restored_access.domain_mappings[0].domain,
            "export.example.test"
        );
        assert_eq!(restored_access.domain_mappings[0].peer_id, "legacy-default");
        assert_eq!(
            restored_config.relay.relays[0].auth_token,
            "expose-relay-token"
        );
        assert!(
            restored
                .domains
                .lock()
                .await
                .mappings
                .contains_key("export.example.test")
        );
        std::fs::remove_file(&state.config_path).unwrap();
        std::fs::remove_file(&restored.config_path).unwrap();
    }

    #[tokio::test]
    async fn multi_peer_backup_import_preserves_all_peer_owners_and_redacts_each_token() {
        let state = test_state("").await;
        let office_endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
        let home_endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
        let office = config::PeerConfig {
            id: "office".into(),
            name: "办公室".into(),
            node_id: office_endpoint.id().to_string(),
            token: "office-token".into(),
            published_targets: Vec::new(),
            relay: config::RelaySettings::default(),
        };
        let home = config::PeerConfig {
            id: "home".into(),
            name: "机房".into(),
            node_id: home_endpoint.id().to_string(),
            token: "home-token".into(),
            published_targets: Vec::new(),
            relay: config::RelaySettings::default(),
        };
        let payload = TransferPayload {
            access: config::AConfig {
                peers: vec![office.clone(), home.clone()],
                mappings: vec![config::Mapping {
                    peer_id: office.id.clone(),
                    allow_loopback_target: false,
                    local: "127.0.0.1:0".into(),
                    host: "10.0.0.10".into(),
                    port: 443,
                    enabled: false,
                    name: "office https".into(),
                    mode: config::MappingMode::Tcp,
                    routes: Vec::new(),
                }],
                domain_mappings: vec![config::DomainMapping {
                    peer_id: home.id.clone(),
                    allow_loopback_target: false,
                    domain: "home.example.test".into(),
                    remote_port: 443,
                    enabled: false,
                }],
                ..Default::default()
            },
            relay: None,
        };
        let app = app(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let persisted = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(persisted.peers.len(), 2);
        assert_eq!(persisted.peer("office"), Some(&office));
        assert_eq!(persisted.peer("home"), Some(&home));
        assert_eq!(persisted.mappings[0].peer_id, "office");
        assert_eq!(persisted.domain_mappings[0].peer_id, "home");

        let exported = response_json(
            app.oneshot(Request::get("/api/export").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(exported["peers"].as_array().unwrap().len(), 2);
        assert!(
            exported["peers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|peer| peer["token"] == "")
        );
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn peer_aware_domain_import_rolls_back_runtime_changes_when_persistence_fails() {
        let mut state = test_state("").await;
        state.config_path = PathBuf::from("/dev/null/powermap-import-domain.toml");
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let node_id = test_link(&state).await.endpoint.id().to_string();
        let domain = "rollback.example.test";
        let imported_peer = default_peer(
            "legacy-default",
            &node_id,
            "import-token",
            config::RelaySettings::default(),
        );
        let access = config::AConfig {
            peers: vec![imported_peer.clone()],
            domain_mappings: vec![config::DomainMapping {
                peer_id: "legacy-default".into(),
                allow_loopback_target: false,
                domain: domain.into(),
                remote_port: 443,
                enabled: true,
            }],
            ..Default::default()
        };
        let payload = serde_json::to_string(&TransferPayload {
            access,
            relay: Some(relay_settings(
                "https://root-relay.example.test",
                "root-relay-token",
            )),
        })
        .unwrap();
        let hosts = state.hosts.clone();
        replace_test_peers(&state, [imported_peer]).await;
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(state.domains.lock().await.mappings.is_empty());
        assert!(state.domains.lock().await.listener.is_none());
        assert!(!hosts.has_loopback(domain).unwrap());
    }

    #[tokio::test]
    async fn failed_domain_import_restores_a_disabled_mapping_without_hosts_marker() {
        let mut state = test_state("").await;
        state.config_path = PathBuf::from("/dev/null/powermap-import-domain-replace.toml");
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let original = config::DomainMapping {
            peer_id: "default".into(),
            allow_loopback_target: false,
            domain: "rollback.example.test".into(),
            remote_port: 443,
            enabled: false,
        };
        state.domains.lock().await.mappings.insert(
            original.domain.clone(),
            disabled_domain_handle(original.clone(), false, None),
        );
        let payload = TransferPayload {
            access: config::AConfig {
                peers: vec![default_peer(
                    "default",
                    "",
                    "",
                    config::RelaySettings::default(),
                )],
                domain_mappings: vec![config::DomainMapping {
                    enabled: true,
                    ..original.clone()
                }],
                ..Default::default()
            },
            relay: None,
        };

        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let restored = {
            let domains = state.domains.lock().await;
            domains.mappings[&original.domain].mapping.clone()
        };
        assert_eq!(*restored.read().await, original);
        assert!(!state.hosts.has_loopback("rollback.example.test").unwrap());
    }

    #[tokio::test]
    async fn legacy_mapping_creation_binds_port_and_domain_mappings_to_the_default_peer() {
        let state = test_state("").await;
        let default = default_peer("legacy-default", "", "", config::RelaySettings::default());
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: vec![default.clone()],
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        replace_test_peers(&state, [default]).await;
        let app = app(state.clone());

        let port = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/mappings")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"local":"127.0.0.1:0","host":"10.0.0.10","port":443,"enabled":false}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(port["peer_id"], "legacy-default");

        let domain = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"domain":"app.example.test","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(domain.status(), StatusCode::OK);

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(saved.mappings[0].peer_id, "legacy-default");
        assert_eq!(saved.domain_mappings[0].peer_id, "legacy-default");
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn legacy_mapping_creation_rejects_a_multi_peer_configuration() {
        let state = test_state("").await;
        let peers = vec![peer("office", "office"), peer("home", "home")];
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: peers.clone(),
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        replace_test_peers(&state, peers).await;
        let app = app(state.clone());

        let port = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:0","host":"10.0.0.10","port":443,"enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(port.status(), StatusCode::BAD_REQUEST);

        let domain = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"domain":"app.example.test","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(domain.status(), StatusCode::BAD_REQUEST);
        assert!(state.inner.lock().await.mappings.is_empty());
        assert!(state.domains.lock().await.mappings.is_empty());
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn mapping_preflight_rejects_a_multi_peer_configuration_before_network_work() {
        let state = test_state("").await;
        let peers = vec![peer("office", "office"), peer("home", "home")];
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: peers.clone(),
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        replace_test_peers(&state, peers).await;
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings/preflight")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:0","host":"10.0.0.10","port":443}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(state.inner.lock().await.mappings.is_empty());
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn peer_owned_mapping_mutations_work_in_multi_peer_configuration() {
        let state = test_state("").await;
        let peers = vec![peer("office", "office"), peer("home", "home")];
        let port_mapping = config::Mapping {
            peer_id: "office".into(),
            allow_loopback_target: false,
            local: "127.0.0.1:0".into(),
            host: "10.0.0.10".into(),
            port: 443,
            enabled: false,
            name: "HTTPS".into(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        let bulk_mapping = config::Mapping {
            local: "127.0.0.1:1".into(),
            enabled: true,
            ..port_mapping.clone()
        };
        let domain_mapping = config::DomainMapping {
            peer_id: "office".into(),
            allow_loopback_target: false,
            domain: "blocked.example.test".into(),
            remote_port: 443,
            // This fixture is intentionally inactive at the handle level. Toggling it off
            // verifies that an existing owner is sufficient without invoking domain preflight.
            enabled: true,
        };
        state.inner.lock().await.mappings.insert(
            port_mapping.local.clone(),
            disabled_handle(port_mapping.clone()),
        );
        state.inner.lock().await.mappings.insert(
            bulk_mapping.local.clone(),
            disabled_handle(bulk_mapping.clone()),
        );
        state.domains.lock().await.mappings.insert(
            domain_mapping.domain.clone(),
            disabled_domain_handle(domain_mapping.clone(), false, None),
        );
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: peers.clone(),
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        replace_test_peers(&state, peers).await;
        let app = app(state.clone());

        let port_update = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/mappings/127.0.0.1:0")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:0","host":"10.0.0.99","port":8443}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(port_update.status(), StatusCode::OK);
        assert_eq!(response_json(port_update).await["peer_id"], "office");

        let port_toggle = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings/127.0.0.1:1/toggle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(port_toggle.status(), StatusCode::OK);
        assert_eq!(response_json(port_toggle).await["peer_id"], "office");

        let port_delete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/mappings/127.0.0.1:0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(port_delete.status(), StatusCode::NO_CONTENT);

        let domain_update = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/domain-mappings/blocked.example.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"domain":"blocked.example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(domain_update.status(), StatusCode::OK);
        assert_eq!(response_json(domain_update).await["peer_id"], "office");

        let domain_toggle = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/domain-mappings/blocked.example.test/toggle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(domain_toggle.status(), StatusCode::OK);
        assert_eq!(response_json(domain_toggle).await["peer_id"], "office");

        let domain_delete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/domain-mappings/blocked.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(domain_delete.status(), StatusCode::NO_CONTENT);

        let bulk_toggle = app
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
        assert_eq!(bulk_toggle.status(), StatusCode::OK);
        assert_eq!(response_json(bulk_toggle).await["changed"], 0);

        let mappings = state.inner.lock().await;
        assert!(!mappings.mappings.contains_key(&port_mapping.local));
        assert_eq!(
            *mappings.mappings[&bulk_mapping.local].mapping.read().await,
            config::Mapping {
                enabled: false,
                ..bulk_mapping
            }
        );
        drop(mappings);
        let domains = state.domains.lock().await;
        assert!(!domains.mappings.contains_key(&domain_mapping.domain));
        assert!(domains.listener.is_none());
        drop(domains);
        assert!(!state.hosts.has_loopback("blocked.example.test").unwrap());
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[tokio::test]
    async fn mapping_creation_rolls_back_when_persistence_fails() {
        let mut state = test_state("").await;
        state.config_path = PathBuf::from("/dev/null/powermap-create-mapping.toml");
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:0","host":"10.0.0.10","port":443,"enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(state.inner.lock().await.mappings.is_empty());
    }

    #[tokio::test]
    async fn peer_switch_restores_the_old_listener_when_persistence_fails() {
        let mut state = test_state("").await;
        state
            .peers
            .upsert_peer(peer("other", "other"))
            .await
            .unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let original = config::Mapping {
            peer_id: "default".into(),
            allow_loopback_target: false,
            local: local.to_string(),
            host: "10.0.0.10".into(),
            port: 443,
            enabled: true,
            name: String::new(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        let handle = start_mapping_owned(&state, original.clone()).await.unwrap();
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(original.local.clone(), handle);
        state.config_path = PathBuf::from("/dev/null/powermap-peer-switch.toml");

        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/mappings/{}", original.local))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"peer_id":"other","local":"{}","host":"10.0.0.11","port":443}}"#,
                        original.local
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let restored = {
            let mappings = state.inner.lock().await;
            mappings.mappings[&original.local].mapping.clone()
        };
        assert_eq!(*restored.read().await, original);
        TcpStream::connect(local).await.unwrap();
    }

    #[tokio::test]
    async fn toggle_all_restores_all_listeners_when_persistence_fails() {
        let mut state = test_state("").await;
        let mut locals = Vec::new();
        for host in ["10.0.0.10", "10.0.0.11"] {
            let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = reserved.local_addr().unwrap();
            drop(reserved);
            let mapping = config::Mapping {
                peer_id: "default".into(),
                allow_loopback_target: false,
                local: local.to_string(),
                host: host.into(),
                port: 443,
                enabled: true,
                name: String::new(),
                mode: config::MappingMode::Tcp,
                routes: Vec::new(),
            };
            let handle = start_mapping_owned(&state, mapping.clone()).await.unwrap();
            state
                .inner
                .lock()
                .await
                .mappings
                .insert(mapping.local.clone(), handle);
            locals.push(mapping.local);
        }
        state.config_path = PathBuf::from("/dev/null/powermap-toggle-all.toml");

        let response = app(state.clone())
            .oneshot(authenticated_post(
                "/api/mappings/toggle-all",
                r#"{"enabled":false}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        for local in locals {
            let mapping = {
                let mappings = state.inner.lock().await;
                mappings.mappings[&local].mapping.clone()
            };
            assert!(mapping.read().await.enabled);
            assert!(TcpListener::bind(&local).await.is_err());
        }
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
            peer_id: String::new(),
            allow_loopback_target: false,
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
    async fn domain_mapping_update_restores_its_old_value_when_persistence_fails() {
        let mut state = test_state("admin-token").await;
        let mapping = config::DomainMapping {
            peer_id: "default".into(),
            allow_loopback_target: false,
            domain: "api.example.test".into(),
            remote_port: 443,
            enabled: false,
        };
        state.domains.lock().await.mappings.insert(
            mapping.domain.clone(),
            disabled_domain_handle(mapping.clone(), false, None),
        );
        state.config_path = PathBuf::from("/dev/null/powermap-domain-update.toml");

        let response = app(state.clone())
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

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let restored = {
            let domains = state.domains.lock().await;
            domains.mappings["api.example.test"].mapping.clone()
        };
        assert_eq!(*restored.read().await, mapping);
    }

    #[tokio::test]
    async fn failed_domain_enable_does_not_leave_a_hosts_marker() {
        let mut state = test_state("admin-token").await;
        state.domain_preflight = Arc::new(|_| Box::pin(async { Ok(()) }));
        let mapping = config::DomainMapping {
            peer_id: "default".into(),
            allow_loopback_target: false,
            domain: "api.example.test".into(),
            remote_port: 443,
            enabled: false,
        };
        state.domains.lock().await.mappings.insert(
            mapping.domain.clone(),
            disabled_domain_handle(mapping.clone(), false, None),
        );
        state.config_path = PathBuf::from("/dev/null/powermap-domain-enable.toml");

        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/domain-mappings/api.example.test")
                    .header(header::AUTHORIZATION, "Bearer admin-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"domain":"api.example.test","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let restored = {
            let domains = state.domains.lock().await;
            domains.mappings["api.example.test"].mapping.clone()
        };
        assert_eq!(*restored.read().await, mapping);
        assert!(!state.hosts.has_loopback("api.example.test").unwrap());
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
        let mut saved = build_config(&state).await.unwrap();
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
        save_config(&state).await.unwrap();

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
            peer_id: String::new(),
            allow_loopback_target: false,
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
                r#"{{"local":"{local}","host":"10.0.0.10","port":6379}}"#
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
                r#"{{"local":"{local}","host":"10.0.0.10","port":6379}}"#
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
                        r#"{{"local":"{local}","host":"10.0.0.11","port":5432}}"#
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
                        r#"{{"local":"{new_local}","host":"10.0.0.11","port":5432}}"#
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
    async fn update_preserves_mapping_peer_ownership_and_loopback_acknowledgement() {
        let state = test_state("").await;
        replace_test_peers(
            &state,
            [default_peer(
                "peer-one",
                "",
                "",
                config::RelaySettings::default(),
            )],
        )
        .await;
        let mapping = config::Mapping {
            peer_id: "peer-one".into(),
            allow_loopback_target: true,
            local: "127.0.0.1:0".into(),
            host: "10.0.0.8".into(),
            port: 8080,
            enabled: false,
            name: "application".into(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(mapping.local.clone(), disabled_handle(mapping.clone()));
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/mappings/{}", mapping.local))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"local":"127.0.0.1:0","host":"10.0.0.9","port":9090,"enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let updated = response_json(response).await;
        assert_eq!(updated["peer_id"], "peer-one");
        assert_eq!(updated["allow_loopback_target"], true);
    }

    #[tokio::test]
    async fn http_route_targets_are_preflighted_on_create_and_update() {
        let state = test_state("").await;
        let (router, requests) = configure_loop_risk_preflight(&state).await;
        let app = app(state.clone());
        let routes = r#"[{"host_match":"service.example.test","target_host":"127.0.0.1","target_port":8080}]"#;

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"127.0.0.1:0","host":"10.0.0.10","port":80,"enabled":false,"mode":"http","routes":{routes},"acknowledge_loop_risk":true}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::BAD_REQUEST);

        let existing = config::Mapping {
            peer_id: String::new(),
            allow_loopback_target: false,
            local: "127.0.0.1:0".into(),
            host: "10.0.0.10".into(),
            port: 80,
            enabled: false,
            name: String::new(),
            mode: config::MappingMode::Http,
            routes: Vec::new(),
        };
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(existing.local.clone(), disabled_handle(existing.clone()));
        let update = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/mappings/{}", existing.local))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"{}","host":"10.0.0.10","port":80,"enabled":false,"mode":"http","routes":{routes},"acknowledge_loop_risk":true}}"#,
                        existing.local
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::BAD_REQUEST);

        let requests = requests.lock().await;
        assert!(requests.iter().any(|request| {
            request.preflight && request.host == "10.0.0.10" && request.port == 80
        }));
        assert!(requests.iter().any(|request| {
            request.preflight && request.host == "127.0.0.1" && request.port == 8080
        }));
        drop(requests);
        router.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn enabling_a_disabled_mapping_repeats_loopback_preflight() {
        let state = test_state("").await;
        let (router, requests) = configure_loop_risk_preflight(&state).await;
        let mapping = config::Mapping {
            peer_id: String::new(),
            allow_loopback_target: true,
            local: "127.0.0.1:0".into(),
            host: "127.0.0.1".into(),
            port: 8080,
            enabled: false,
            name: String::new(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
        };
        state
            .inner
            .lock()
            .await
            .mappings
            .insert(mapping.local.clone(), disabled_handle(mapping.clone()));
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/mappings/{}/toggle", mapping.local))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !state.inner.lock().await.mappings[&mapping.local]
                .mapping
                .read()
                .await
                .enabled
        );
        assert!(requests.lock().await.iter().any(|request| {
            request.preflight && request.host == "127.0.0.1" && request.port == 8080
        }));
        router.shutdown().await.unwrap();
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
                r#"{{"local":"{local}","host":"10.0.0.10","port":6379}}"#
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
        let app = app(state.clone());

        let create = Request::builder()
            .method("POST")
            .uri("/api/mappings")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"local":"{local}","host":"10.0.0.10","port":6379,"name":"Redis 主库"}}"#
            )))
            .unwrap();
        let created = response_json(app.clone().oneshot(create).await.unwrap()).await;
        assert_eq!(created["name"], "Redis 主库");
        assert_eq!(created["peer_id"], "default");

        let listed = response_json(
            app.oneshot(Request::get("/api/mappings").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed[0]["name"], "Redis 主库");
        assert_eq!(listed[0]["peer_id"], "default");

        let saved = config::load_config(&state.config_path, None)
            .unwrap()
            .config
            .access
            .unwrap();
        assert_eq!(saved.mappings[0].peer_id, "default");
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
                    r#"{{"local":"{local}","host":"10.0.0.10","port":6379}}"#
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
                r#"{{"local":"{existing_local}","host":"10.0.0.10","port":6379}}"#
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
                        "host": "10.0.0.10",
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
                r#"{{"local":"{local}","host":"10.0.0.10","port":6379}}"#
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
                r#"{{"local":"{local}","host":"10.0.0.10","port":6379}}"#
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
                        r#"{{"local":"{local}","host":"10.0.0.10","port":80}}"#
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

    #[test]
    fn target_preflight_status_surfaces_loopback_as_structured_warning() {
        let (check, loop_risk) = target_preflight_check(
            proto::OpenStatus::LoopRisk("target resolves to loopback".into()),
            "127.0.0.1",
            443,
        );

        assert!(!check.ok);
        assert!(check.detail.contains("loopback"));
        assert_eq!(loop_risk.unwrap().message, "target resolves to loopback");
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
    async fn diagnostics_api_reports_unconfigured_disconnected_node() {
        let app = app(test_state("").await);
        let response = app
            .oneshot(
                Request::get("/api/diagnostics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["transport"], "disconnected");
        assert_eq!(body["configuration"]["credential_configured"], false);
        assert!(body["connected_peer_ips"].as_array().unwrap().is_empty());
        assert_eq!(
            body["recommendation"],
            "Configure the server credential, then retry the connection."
        );
    }

    #[tokio::test]
    async fn runtime_api_exposes_local_process_metadata() {
        let state = test_state("").await;
        let expected_config_path = state.config_path.to_string_lossy().into_owned();
        let app = app(state);

        let response = app
            .oneshot(Request::get("/api/runtime").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["pid"], std::process::id());
        assert_eq!(body["config_path"], expected_config_path);
        assert!(body["platform"]["os"].as_str().is_some());
        assert!(body["supervisor"]["kind"].as_str().is_some());
        assert!(body["privilege"]["level"].as_str().is_some());
    }

    #[tokio::test]
    async fn onboarding_api_reports_stable_first_use_state() {
        let app = app(test_state("").await);
        let response = app
            .oneshot(Request::get("/api/onboarding").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["credential_configured"], false);
        assert_eq!(body["mappings"], 0);
        assert_eq!(body["complete"], false);
    }

    #[tokio::test]
    async fn templates_and_local_service_routes_are_read_only() {
        let app = app(test_state("").await);
        let templates = app
            .clone()
            .oneshot(
                Request::get("/api/mapping-templates")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(templates.status(), StatusCode::OK);
        let templates = response_json(templates).await;
        assert!(
            templates
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["id"] == "ssh")
        );

        let services = app
            .oneshot(
                Request::get("/api/local-services")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(services.status(), StatusCode::OK);
        let services = response_json(services).await;
        assert!(
            services
                .as_array()
                .unwrap()
                .iter()
                .all(|item| { matches!(item["address"].as_str(), Some("127.0.0.1" | "::1")) })
        );
    }

    #[tokio::test]
    async fn health_report_and_port_suggestion_apis_are_bounded_and_redacted() {
        let state = test_state("").await;
        state.events.push(
            "info",
            "credential",
            "updated token=never-expose-this-value",
        );
        let app = app(state);

        let health = app
            .clone()
            .oneshot(
                Request::get("/api/mapping-health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(response_json(health).await["total"], 0);

        let report = app
            .clone()
            .oneshot(
                Request::get("/api/diagnostic-report")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(report.status(), StatusCode::OK);
        let report = response_json(report).await;
        assert!(
            report["recent_events"][0]
                .as_str()
                .unwrap()
                .contains("<redacted>")
        );
        assert!(!report.to_string().contains("never-expose-this-value"));

        let suggestions = app
            .oneshot(
                Request::get("/api/mappings/port-suggestions?preferred=38080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(suggestions.status(), StatusCode::OK);
        let suggestions = response_json(suggestions).await;
        let suggestions = suggestions.as_array().unwrap();
        assert!(suggestions.len() <= 5);
        assert!(suggestions.iter().all(|item| item["host"] == "127.0.0.1"));
    }

    #[tokio::test]
    async fn export_is_redacted_unless_credentials_are_explicitly_requested() {
        let state = test_state("").await;
        let link = test_link(&state).await;
        let target = link.endpoint.id();
        link.set_creds(target.to_string(), "private-token".into(), target, vec![])
            .await;
        {
            let mut relay = link.relay.lock().await;
            relay.settings = config::RelaySettings {
                relays: vec![config::RelayEntry {
                    url: "https://export-relay.example.com".into(),
                    auth_token: "relay-secret".into(),
                }],
                force_relay: false,
            };
        }
        let app = app(state);

        let redacted = response_json(
            app.clone()
                .oneshot(Request::get("/api/export").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            redacted["peers"][0]["relay"]["relays"][0]["url"],
            "https://export-relay.example.com"
        );
        assert_eq!(redacted["peers"][0]["token"], "");
        assert!(
            redacted["peers"][0]["relay"]["relays"][0]
                .get("auth_token")
                .is_none()
        );

        let full = response_json(
            app.oneshot(
                Request::get("/api/export?include_credentials=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(full["peers"][0]["token"], "private-token");
        assert_eq!(
            full["peers"][0]["relay"]["relays"][0]["auth_token"],
            "relay-secret"
        );
    }

    #[tokio::test]
    async fn import_applies_relay_when_the_transfer_payload_includes_it() {
        let app = app(test_state("").await);
        let payload = r#"{
            "node_id": "",
            "token": "",
            "relay": {
                "relays": [{
                    "url": "https://imported-relay.example.com",
                    "auth_token": "imported-relay-token"
                }],
                "force_relay": true
            }
        }"#;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let relay = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(relay.status(), StatusCode::OK);
        let relay = response_json(relay).await;
        assert_eq!(
            relay["relays"][0]["url"],
            "https://imported-relay.example.com"
        );
        assert_eq!(relay["relays"][0]["auth_token"], "imported-relay-token");
        assert_eq!(relay["force_relay"], true);
    }

    #[tokio::test]
    async fn import_returns_an_error_and_restores_relay_when_persistence_fails() {
        let mut state = test_state("").await;
        state.config_path = PathBuf::from("/dev/null/powermap-import.toml");
        let app = app(state);
        let payload = r#"{
            "node_id": "",
            "token": "",
            "relay": {
                "relays": [{
                    "url": "https://imported-relay.example.com",
                    "auth_token": "imported-relay-token"
                }],
                "force_relay": true
            }
        }"#;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let relay = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let relay = response_json(relay).await;
        assert_eq!(relay["relays"], serde_json::json!([]));
        assert_eq!(relay["force_relay"], false);
    }

    #[tokio::test]
    async fn old_import_payload_without_relay_preserves_the_local_relay_configuration() {
        let state = test_state("").await;
        test_link(&state)
            .await
            .set_relay(config::RelaySettings {
                relays: vec![config::RelayEntry {
                    url: "https://local-relay.example.com".into(),
                    auth_token: "local-relay-token".into(),
                }],
                force_relay: false,
            })
            .await
            .unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"node_id":"","token":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let relay = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let relay = response_json(relay).await;
        assert_eq!(relay["relays"][0]["url"], "https://local-relay.example.com");
        assert_eq!(relay["relays"][0]["auth_token"], "local-relay-token");
    }

    #[tokio::test]
    async fn credential_view_preserves_published_targets_for_the_console() {
        let state = test_state("").await;
        let link = test_link(&state).await;
        let node_id = link.endpoint.id().to_string();
        let target = parse_target(&node_id).unwrap();
        link.set_creds(
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
    async fn shared_credential_applies_the_optional_relay_configuration() {
        let state = test_state("").await;
        let node_id = test_link(&state).await.endpoint.id().to_string();
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"node_id":"{node_id}","token":"access-token","relay":{{"relays":[{{"url":"https://relay-a.example.com","auth_token":"relay-a-token"}},{{"url":"https://relay-b.example.com","auth_token":"relay-b-token"}}],"force_relay":true}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(
            body["relay"]["relays"][0]["url"],
            "https://relay-a.example.com"
        );
        assert_eq!(body["relay"]["relays"][0]["auth_token"], "relay-a-token");
        assert_eq!(body["relay"]["relays"][1]["auth_token"], "relay-b-token");
        assert_eq!(body["relay"]["force_relay"], true);
    }

    #[tokio::test]
    async fn shared_credential_reverts_runtime_state_when_persistence_fails() {
        let mut state = test_state("").await;
        let node_id = test_link(&state).await.endpoint.id().to_string();
        state.config_path = PathBuf::from("/dev/null/powermap-credential.toml");
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"node_id":"{node_id}","token":"access-token","relay":{{"relays":[{{"url":"https://relay.example.com","auth_token":"relay-token"}}],"force_relay":true}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let credential = app
            .clone()
            .oneshot(Request::get("/api/credential").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let credential = response_json(credential).await;
        assert_eq!(credential["configured"], false);
        assert_eq!(credential["node_id"], "");

        let relay = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response_json(relay).await["relays"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn shared_credential_without_relay_preserves_local_relay_configuration() {
        let state = test_state("").await;
        let link = test_link(&state).await;
        let node_id = link.endpoint.id().to_string();
        {
            let mut relay = link.relay.lock().await;
            relay.settings = config::RelaySettings {
                relays: vec![config::RelayEntry {
                    url: "https://local-relay.example.com".into(),
                    auth_token: "local-relay-token".into(),
                }],
                force_relay: false,
            };
        }
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"node_id":"{node_id}","token":"access-token"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(
            body["relay"]["relays"][0]["url"],
            "https://local-relay.example.com"
        );
        assert_eq!(
            body["relay"]["relays"][0]["auth_token"],
            "local-relay-token"
        );
    }

    #[tokio::test]
    async fn relay_api_updates_the_runtime_configuration() {
        let app = app(test_state("").await);
        let relay = r#"{"relays":[{"url":"https://relay.example.com","auth_token":"relay-token"}],"force_relay":false}"#;

        let updated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/relay")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(relay))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);
        let updated = response_json(updated).await;
        assert_eq!(updated["relays"][0]["auth_token"], "relay-token");
        assert_eq!(updated["force_relay"], false);

        let current = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(current.status(), StatusCode::OK);
        let current = response_json(current).await;
        assert_eq!(current["relays"][0]["url"], "https://relay.example.com");
        assert_eq!(current["force_relay"], false);
    }

    #[tokio::test]
    async fn relay_api_marks_a_force_relay_change_for_restart() {
        let state = test_state("").await;
        let link = test_link(&state).await;
        let app = app(state);
        let relay = r#"{"relays":[],"force_relay":true}"#;

        let updated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/relay")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(relay))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);
        assert_eq!(response_json(updated).await["restart_required"], true);

        let current = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response_json(current).await["restart_required"], true);
        assert!(!link.can_open_new_connections().await);
    }

    #[tokio::test]
    async fn relay_probe_api_skips_the_embedded_official_relay() {
        let app = app(test_state("").await);
        let response = app
            .oneshot(
                Request::get("/api/relay/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await["relays"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn relay_probe_rejects_a_multi_peer_configuration_before_outbound_io() {
        let state = test_state("").await;
        let peers = vec![peer("office", "office"), peer("home", "home")];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_url = format!("https://{}", listener.local_addr().unwrap());
        test_link(&state)
            .await
            .set_relay(relay_settings(&relay_url, ""))
            .await
            .unwrap();
        config::save(
            &state.config_path,
            &config::Config {
                relay: config::RelaySettings::default(),
                expose: None,
                access: Some(config::AConfig {
                    peers: peers.clone(),
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        replace_test_peers(&state, peers).await;
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::get("/api/relay/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        std::fs::remove_file(&state.config_path).unwrap();
    }

    #[test]
    fn relay_probe_uses_iroh_ping_endpoint() {
        assert_eq!(
            relay_probe_url("https://relay.example.com:18443").unwrap(),
            "https://relay.example.com:18443/ping"
        );
        assert!(relay_probe_url("not a relay").is_none());
    }

    #[test]
    fn relay_probe_never_sends_a_relay_token() {
        let custom = config::RelayEntry {
            url: "https://private-relay.example.com".into(),
            auth_token: "custom-relay-token".into(),
        };
        let request = relay_probe_request(&reqwest::Client::new(), &custom)
            .unwrap()
            .build()
            .unwrap();

        assert!(request.headers().get(header::AUTHORIZATION).is_none());
    }

    #[tokio::test]
    async fn relay_api_reverts_the_runtime_change_when_persistence_fails() {
        let mut state = test_state("").await;
        state.config_path = PathBuf::from("/dev/null/powermap-relay.toml");
        let app = app(state);
        let relay =
            r#"{"relays":[{"url":"https://relay.example.com","auth_token":"relay-token"}]}"#;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/relay")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(relay))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let current = app
            .oneshot(Request::get("/api/relay").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response_json(current).await["relays"],
            serde_json::json!([])
        );
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
        let link = test_link(&state).await;
        let old_target = link.endpoint.id();
        {
            let mut creds = link.creds.write().await;
            creds.node_id = old_target.to_string();
            creds.token = "old-token".into();
            creds.target = Some(old_target);
        }

        let reserved_old = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_local = reserved_old.local_addr().unwrap();
        drop(reserved_old);
        let old_mapping = config::Mapping {
            peer_id: String::new(),
            allow_loopback_target: false,
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
        let expected_old_mapping = config::Mapping {
            peer_id: "default".into(),
            ..old_mapping
        };
        assert_eq!(*old_runtime_mapping.read().await, expected_old_mapping);
        TcpStream::connect(old_local).await.unwrap();

        let creds = link.creds.read().await;
        assert_eq!(creds.node_id, old_target.to_string());
        assert_eq!(creds.token, "old-token");
    }

    #[tokio::test]
    async fn failed_peer_change_rebuild_rolls_back_all_import_staging() {
        let mut state = test_state("").await;
        let original_other = peer("other", "原始对端");
        state
            .peers
            .upsert_peer(original_other.clone())
            .await
            .unwrap();

        // Fail exactly the replacement bind. The old listener has already been stopped at that
        // point; the next bind succeeds so rollback can prove it restored that listener.
        let fail_next_bind = Arc::new(AtomicBool::new(false));
        let bind_flag = fail_next_bind.clone();
        state.mapping_listener = Arc::new(move |local| {
            let bind_flag = bind_flag.clone();
            Box::pin(async move {
                if bind_flag.swap(false, Ordering::SeqCst) {
                    Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "forced replacement bind failure",
                    ))
                } else {
                    TcpListener::bind(local).await
                }
            })
        });

        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let old_mapping = config::Mapping {
            peer_id: "default".into(),
            allow_loopback_target: false,
            local: local.to_string(),
            host: "10.0.0.10".into(),
            port: 443,
            enabled: true,
            name: "现有映射".into(),
            mode: config::MappingMode::Tcp,
            routes: Vec::new(),
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
        assert_eq!(state.peers.link_count().await, 1);

        let imported_other = peer("other", "导入对端");
        let payload = TransferPayload {
            access: config::AConfig {
                peers: vec![
                    default_peer("default", "", "", config::RelaySettings::default()),
                    imported_other,
                ],
                // This disabled mapping and domain mapping are successfully staged before the
                // peer-change rebuild below, and must not leak when that rebuild fails.
                mappings: vec![
                    config::Mapping {
                        peer_id: "other".into(),
                        allow_loopback_target: false,
                        local: "127.0.0.1:0".into(),
                        host: "10.0.0.11".into(),
                        port: 8443,
                        enabled: false,
                        name: "暂存映射".into(),
                        mode: config::MappingMode::Tcp,
                        routes: Vec::new(),
                    },
                    config::Mapping {
                        peer_id: "other".into(),
                        ..old_mapping.clone()
                    },
                ],
                domain_mappings: vec![config::DomainMapping {
                    peer_id: "other".into(),
                    allow_loopback_target: false,
                    domain: "staged-rollback.example.test".into(),
                    remote_port: 443,
                    enabled: false,
                }],
                ..Default::default()
            },
            relay: None,
        };
        fail_next_bind.store(true, Ordering::SeqCst);

        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let restored = {
            let mappings = state.inner.lock().await;
            assert_eq!(mappings.mappings.len(), 1);
            mappings.mappings[&old_mapping.local].mapping.clone()
        };
        assert_eq!(*restored.read().await, old_mapping);
        TcpStream::connect(local).await.unwrap();
        assert!(state.domains.lock().await.mappings.is_empty());
        assert_eq!(state.peers.link_count().await, 1);
        assert_eq!(
            state.peers.peer_config("other").await.unwrap().name,
            original_other.name
        );
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

#[derive(Deserialize)]
struct PeerBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    published_targets: Option<Vec<config::PublishedTarget>>,
    #[serde(default)]
    relay: Option<config::RelaySettings>,
}

impl PeerBody {
    fn apply_to(self, mut peer: config::PeerConfig) -> config::PeerConfig {
        if let Some(name) = self.name {
            peer.name = name.trim().to_owned();
        }
        if let Some(node_id) = self.node_id {
            peer.node_id = node_id.trim().to_owned();
        }
        if let Some(token) = self.token {
            peer.token = token.trim().to_owned();
        }
        if let Some(published_targets) = self.published_targets {
            peer.published_targets = published_targets;
        }
        if let Some(relay) = self.relay {
            peer.relay = relay;
        }
        peer
    }
}

#[derive(Serialize)]
struct PeerDeleteConflict {
    peer_id: String,
    mappings: Vec<String>,
    domain_mappings: Vec<String>,
    reverse_mapping: bool,
}

#[derive(Serialize)]
struct PeerApiView {
    #[serde(flatten)]
    peer: config::PeerConfig,
    connected: bool,
    restart_required: bool,
    mapping_count: usize,
}

async fn peer_mapping_counts(st: &AppState) -> HashMap<String, usize> {
    let mappings = st
        .inner
        .lock()
        .await
        .mappings
        .values()
        .map(|handle| handle.mapping.clone())
        .collect::<Vec<_>>();
    let domains = st
        .domains
        .lock()
        .await
        .mappings
        .values()
        .map(|handle| handle.mapping.clone())
        .collect::<Vec<_>>();
    let mut counts = HashMap::new();
    for mapping in mappings {
        let peer_id = mapping.read().await.peer_id.clone();
        *counts.entry(peer_id).or_default() += 1;
    }
    for mapping in domains {
        let peer_id = mapping.read().await.peer_id.clone();
        *counts.entry(peer_id).or_default() += 1;
    }
    counts
}

async fn peer_api_views(st: &AppState) -> Vec<PeerApiView> {
    let views = st.peers.peer_views().await;
    let counts = peer_mapping_counts(st).await;
    let mut result = st
        .peers
        .peer_configs()
        .await
        .into_iter()
        .map(|peer| {
            let view = views.iter().find(|view| view.id == peer.id);
            PeerApiView {
                connected: view.is_some_and(|view| view.connected),
                restart_required: view.is_some_and(|view| view.restart_required),
                mapping_count: counts.get(&peer.id).copied().unwrap_or_default(),
                peer,
            }
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| a.peer.name.cmp(&b.peer.name));
    result
}

async fn peer_api_view(st: &AppState, peer: config::PeerConfig) -> PeerApiView {
    peer_api_views(st)
        .await
        .into_iter()
        .find(|view| view.peer.id == peer.id)
        .expect("a configured peer must be visible through PeerManager")
}

async fn persist_peer_state(st: &AppState) -> Result<(), String> {
    let _save = st.config_save.lock().await;
    let mut cfg = config::load_config(&st.config_path, None)
        .map_err(|error| format!("读取配置失败: {error}"))?
        .config;
    cfg.access = Some(build_config(st).await?);
    cfg.normalize_access_peers()?;
    cfg.validate()?;
    config::save(&st.config_path, &cfg).map_err(|error| format!("写入配置失败: {error}"))
}

async fn list_peers(State(st): State<AppState>) -> Json<Vec<PeerApiView>> {
    Json(peer_api_views(&st).await)
}

async fn create_peer(
    State(st): State<AppState>,
    Json(body): Json<PeerBody>,
) -> Result<Json<PeerApiView>, (StatusCode, String)> {
    let peer = body.apply_to(config::PeerConfig {
        id: config::new_peer_id(),
        name: String::new(),
        node_id: String::new(),
        token: String::new(),
        published_targets: Vec::new(),
        relay: config::RelaySettings::default(),
    });
    st.peers
        .upsert_peer(peer.clone())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    if let Err(error) = persist_peer_state(&st).await {
        let _ = st.peers.remove_peer(&peer.id).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存对端失败: {error}"),
        ));
    }
    st.events
        .push("info", "peer", format!("已创建对端 {}", peer.name));
    Ok(Json(peer_api_view(&st, peer).await))
}

async fn update_peer(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PeerBody>,
) -> Result<Json<PeerApiView>, (StatusCode, String)> {
    let previous = st
        .peers
        .peer_config(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, format!("未知 peer_id {id}")))?;
    let peer = body.apply_to(previous.clone());
    st.peers
        .upsert_peer(peer.clone())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    if let Err(error) = persist_peer_state(&st).await {
        if let Err(rollback_error) = st.peers.upsert_peer(previous).await {
            tracing::error!(error = %rollback_error, "保存对端失败后无法恢复运行时配置");
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存对端失败: {error}"),
        ));
    }
    st.events
        .push("info", "peer", format!("已更新对端 {}", peer.name));
    Ok(Json(peer_api_view(&st, peer).await))
}

async fn delete_peer(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let previous = match st.peers.peer_config(&id).await {
        Ok(peer) => peer,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mappings = {
        let handles = st
            .inner
            .lock()
            .await
            .mappings
            .values()
            .map(|handle| handle.mapping.clone())
            .collect::<Vec<_>>();
        let mut owners = Vec::new();
        for mapping in handles {
            let mapping = mapping.read().await;
            if mapping.peer_id == id {
                owners.push(mapping.local.clone());
            }
        }
        owners
    };
    let domain_mappings = {
        let handles = st
            .domains
            .lock()
            .await
            .mappings
            .values()
            .map(|handle| handle.mapping.clone())
            .collect::<Vec<_>>();
        let mut owners = Vec::new();
        for mapping in handles {
            let mapping = mapping.read().await;
            if mapping.peer_id == id {
                owners.push(mapping.domain.clone());
            }
        }
        owners
    };
    let reverse_mapping = {
        let reverse = st.reverse.read().await;
        reverse.enabled && reverse.peer_id == previous.id
    };
    if !mappings.is_empty() || !domain_mappings.is_empty() || reverse_mapping {
        return (
            StatusCode::CONFLICT,
            Json(PeerDeleteConflict {
                peer_id: id,
                mappings,
                domain_mappings,
                reverse_mapping,
            }),
        )
            .into_response();
    }
    if let Err(error) = st.peers.remove_peer(&previous.id).await {
        return (StatusCode::CONFLICT, error).into_response();
    }
    if let Err(error) = persist_peer_state(&st).await {
        if let Err(rollback_error) = st.peers.upsert_peer(previous).await {
            tracing::error!(error = %rollback_error, "删除对端保存失败后无法恢复运行时配置");
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存对端失败: {error}"),
        )
            .into_response();
    }
    st.events.push("info", "peer", format!("已删除对端 {id}"));
    StatusCode::NO_CONTENT.into_response()
}

/// A domain mapping's public lifecycle state. `local_listener` is true only while the
/// mapping owns its injected loopback listener; `hosts_managed` refers only to PowerMap's
/// exact marker, never an unrelated hosts-file entry.
#[derive(Serialize)]
pub struct DomainMappingStatus {
    peer_id: String,
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
        peer_id: mapping.peer_id.clone(),
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
    #[serde(default)]
    peer_id: Option<String>,
    domain: String,
    /// POST defaults to HTTPS; PUT preserves the existing value when omitted.
    #[serde(default)]
    remote_port: Option<u16>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    allow_loopback_target: Option<bool>,
    #[serde(default)]
    acknowledge_loop_risk: Option<bool>,
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
        peer_id: None,
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
        preflight: true,
        allow_loopback_target: mapping.allow_loopback_target,
    };
    match tokio::time::timeout(
        Duration::from_secs(8),
        open_preflight_with_retry(link, &request),
    )
    .await
    {
        Ok(Ok(proto::OpenStatus::Ok)) => Ok(()),
        Ok(Ok(proto::OpenStatus::LoopRisk(message))) => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{}:{} 解析为 loopback 目标：{message}",
                mapping.domain, mapping.remote_port
            ),
        )),
        Ok(Ok(proto::OpenStatus::Error(error))) => Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "无法从 expose 端验证 {}:{}：{}",
                mapping.domain, mapping.remote_port, error
            ),
        )),
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
    mut mapping: config::DomainMapping,
) -> Result<Arc<DomainMappingHandle>, (StatusCode, String)> {
    mapping.peer_id = st
        .peers
        .resolve_mapping_peer_id(&mapping.peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
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
    let peer_id = mapping.peer_id.clone();
    let link = st
        .peers
        .acquire_link(&peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    st.peers
        .watch_link(peer_id.clone(), link, st.metrics.clone(), st.events.clone())
        .await;
    if let Err(reason) = mapping.validate() {
        st.peers.release_link(&peer_id).await;
        return Err((StatusCode::BAD_REQUEST, reason));
    }
    if let Err(error) = (st.domain_admin_check)().map_err(domain_authority_http) {
        st.peers.release_link(&peer_id).await;
        return Err(error);
    }
    if let Err(error) = (st.domain_preflight)(&mapping).await {
        st.peers.release_link(&peer_id).await;
        return Err(error);
    }

    let listener_was_started = st.domains.lock().await.listener.is_none();
    if listener_was_started {
        let listener = match (st.domain_listener)().await {
            Ok(listener) => listener,
            Err(error) => {
                st.peers.release_link(&peer_id).await;
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
        st.peers.release_link(&peer_id).await;
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
        peer_id: Some(peer_id),
    }))
}

async fn start_shared_domain_listener(st: &AppState, listener: TcpListener) {
    let domains = st.domains.clone();
    let peers = st.peers.clone();
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
                    let peers = peers.clone();
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
                        let peer_id = mapping.peer_id.clone();
                        let link = match peers.get_link(&peer_id).await {
                            Ok(link) => link,
                            Err(error) => {
                                tracing::warn!(error = %error, sni, "域名映射对端不可用");
                                return;
                            }
                        };
                        let request = proto::OpenRequest {
                            token: link.token().await,
                            host: mapping.domain.clone(),
                            port: mapping.remote_port,
                            kind: proto::TunnelKind::Tcp,
                            register: false,
                            preflight: false,
                            allow_loopback_target: mapping.allow_loopback_target,
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
    if let Some(peer_id) = &handle.peer_id {
        st.peers.release_link(peer_id).await;
    }
    hosts_result
}

/// Serializes all ownership transitions without retaining attacker-controlled domain keys.
async fn lock_domain_operation(st: &AppState) -> tokio::sync::MutexGuard<'_, ()> {
    st.domain_lifecycle.lock().await
}

/// Serializes port mapping replacement, persistence, and rollback as one operation.
async fn lock_mapping_operation(st: &AppState) -> tokio::sync::MutexGuard<'_, ()> {
    st.mapping_lifecycle.lock().await
}

async fn record_domain_cleanup_failure(st: &AppState, domain: &str, error: String) {
    let domains = st.domains.lock().await;
    if let Some(handle) = domains.mappings.get(domain) {
        handle.hosts_managed.store(true, Ordering::Relaxed);
        *handle.last_error.write().await = Some(error);
    }
}

fn domain_handle_owns_hosts_marker(handle: &DomainMappingHandle) -> bool {
    handle.hosts_managed.load(Ordering::Relaxed)
}

async fn create_domain_mapping(
    State(st): State<AppState>,
    Json(body): Json<DomainMappingBody>,
) -> Result<Json<DomainMappingStatus>, (StatusCode, String)> {
    let peer_id = st
        .peers
        .resolve_mapping_peer_id(body.peer_id.as_deref().unwrap_or_default())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
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
        peer_id,
        allow_loopback_target: loopback_acknowledged(
            body.acknowledge_loop_risk,
            body.allow_loopback_target,
            false,
        ),
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
    if let Err(error) = persist_peer_state(&st).await {
        let handle = st.domains.lock().await.mappings.remove(&mapping.domain);
        if let Some(handle) = handle
            && let Err(cleanup_error) = stop_domain_mapping(&st, handle, true).await
        {
            tracing::error!(error = %cleanup_error, domain = %mapping.domain, "域名映射保存失败后的回滚不完整");
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存域名映射失败: {error}"),
        ));
    }
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
    let peer_id = st
        .peers
        .resolve_mapping_peer_id(body.peer_id.as_deref().unwrap_or(&old_mapping.peer_id))
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mapping = config::DomainMapping {
        peer_id,
        allow_loopback_target: loopback_acknowledged(
            body.acknowledge_loop_risk,
            body.allow_loopback_target,
            old_mapping.allow_loopback_target,
        ),
        domain: body.domain,
        remote_port: body.remote_port.unwrap_or(old_mapping.remote_port),
        enabled: body.enabled.unwrap_or(old_mapping.enabled),
    };
    mapping
        .validate()
        .map_err(|reason| (StatusCode::BAD_REQUEST, reason))?;
    if mapping.enabled == old_mapping.enabled && mapping.peer_id == old_mapping.peer_id {
        // This changes the remote destination without rebuilding the shared loopback socket.
        // Validate it before exposing the new value to future connections or persistence.
        if mapping.enabled
            && (mapping.remote_port != old_mapping.remote_port
                || mapping.allow_loopback_target != old_mapping.allow_loopback_target)
        {
            (st.domain_preflight)(&mapping).await?;
        }
        *old_handle.write().await = mapping;
        let domains = st.domains.lock().await;
        let handle = domains.mappings.get(&domain).expect("域名映射仍存在");
        let status = domain_status(handle).await;
        drop(domains);
        if let Err(error) = persist_peer_state(&st).await {
            *old_handle.write().await = old_mapping;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存域名映射失败: {error}"),
            ));
        }
        return Ok(Json(status));
    }
    let handle = start_domain_mapping_owned(&st, mapping.clone()).await?;
    let enabled = mapping.enabled;
    let old = st
        .domains
        .lock()
        .await
        .mappings
        .insert(domain.clone(), handle)
        .expect("已确认存在域名映射");
    let remove_replacement_hosts = !domain_handle_owns_hosts_marker(&old);
    if let Err(error) = persist_peer_state(&st).await {
        let replacement = st.domains.lock().await.mappings.insert(domain, old);
        if let Some(replacement) = replacement
            && let Err(cleanup_error) =
                stop_domain_mapping(&st, replacement, remove_replacement_hosts).await
        {
            tracing::error!(error = %cleanup_error, "域名映射保存失败后回滚新把手不完整");
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存域名映射失败: {error}"),
        ));
    }
    if let Err(error) = stop_domain_mapping(&st, old, !enabled).await {
        tracing::error!(%error, "替换域名映射后清理旧 hosts 条目失败");
        if !enabled {
            record_domain_cleanup_failure(&st, &domain, error).await;
            if let Err(persist_error) = persist_peer_state(&st).await {
                tracing::error!(error = %persist_error, "无法保存域名映射 hosts 清理失败状态");
            }
        }
    }
    let status = {
        let domains = st.domains.lock().await;
        domain_status(domains.mappings.get(&domain).expect("域名映射仍存在")).await
    };
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
        .insert(domain.clone(), handle)
        .expect("已确认存在域名映射");
    let remove_replacement_hosts = !domain_handle_owns_hosts_marker(&old);
    if let Err(error) = persist_peer_state(&st).await {
        let replacement = st.domains.lock().await.mappings.insert(domain, old);
        if let Some(replacement) = replacement
            && let Err(cleanup_error) =
                stop_domain_mapping(&st, replacement, remove_replacement_hosts).await
        {
            tracing::error!(error = %cleanup_error, "域名映射保存失败后回滚新把手不完整");
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存域名映射失败: {error}"),
        ));
    }
    if let Err(error) = stop_domain_mapping(&st, old, !enabled).await {
        tracing::error!(%error, "停用域名映射后清理 hosts 条目失败");
        if !enabled {
            record_domain_cleanup_failure(&st, &domain, error).await;
            if let Err(persist_error) = persist_peer_state(&st).await {
                tracing::error!(error = %persist_error, "无法保存域名映射 hosts 清理失败状态");
            }
        }
    }
    let status = {
        let domains = st.domains.lock().await;
        domain_status(domains.mappings.get(&domain).expect("域名映射仍存在")).await
    };
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
            // Persist an explicit disabled recovery record before touching hosts or the shared
            // listener. A write failure can then put the still-live original handle straight
            // back, and a hosts cleanup failure remains recoverable after restart.
            let mut recovery_mapping = handle.mapping.read().await.clone();
            recovery_mapping.enabled = false;
            st.domains.lock().await.mappings.insert(
                domain.clone(),
                disabled_domain_handle(recovery_mapping, true, None),
            );
            if let Err(error) = persist_peer_state(&st).await {
                st.domains
                    .lock()
                    .await
                    .mappings
                    .insert(domain.clone(), handle);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("保存域名映射失败: {error}"),
                )
                    .into_response();
            }
            match stop_domain_mapping(&st, handle, true).await {
                Ok(()) => {
                    let recovery = st.domains.lock().await.mappings.remove(&domain);
                    if let Err(error) = persist_peer_state(&st).await {
                        if let Some(recovery) = recovery {
                            st.domains
                                .lock()
                                .await
                                .mappings
                                .insert(domain.clone(), recovery);
                        }
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("保存域名映射失败: {error}"),
                        )
                            .into_response();
                    }
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(error) => {
                    if let Some(recovery) = st.domains.lock().await.mappings.get(&domain) {
                        *recovery.last_error.write().await = Some(error.clone());
                    }
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
    peer_id: String,
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
            peer_id: mapping.peer_id.clone(),
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
    /// Immutable remote owner. Legacy callers may omit this only while one migrated default peer
    /// exists; multi-peer callers must choose an explicit ID.
    #[serde(default)]
    peer_id: Option<String>,
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
    #[serde(default)]
    allow_loopback_target: Option<bool>,
    /// UI-facing spelling for the persisted loopback acknowledgement flag.
    #[serde(default)]
    acknowledge_loop_risk: Option<bool>,
}

fn loopback_acknowledged(
    acknowledge_loop_risk: Option<bool>,
    allow_loopback_target: Option<bool>,
    fallback: bool,
) -> bool {
    acknowledge_loop_risk
        .or(allow_loopback_target)
        .unwrap_or(fallback)
}

#[derive(Serialize)]
struct PreflightCheck {
    ok: bool,
    detail: String,
}

#[derive(Serialize)]
struct PreflightResult {
    ready: bool,
    loop_risk: Option<LoopRisk>,
    checks: BTreeMap<&'static str, PreflightCheck>,
}

#[derive(Serialize)]
struct LoopRisk {
    message: String,
}

fn target_preflight_check(
    status: proto::OpenStatus,
    host: &str,
    port: u16,
) -> (PreflightCheck, Option<LoopRisk>) {
    match status {
        proto::OpenStatus::Ok => (
            PreflightCheck {
                ok: true,
                detail: format!("{host}:{port} 可由 server 端访问"),
            },
            None,
        ),
        proto::OpenStatus::LoopRisk(message) => (
            PreflightCheck {
                ok: false,
                detail: message.clone(),
            },
            Some(LoopRisk { message }),
        ),
        proto::OpenStatus::Error(message) => (
            PreflightCheck {
                ok: false,
                detail: message,
            },
            None,
        ),
    }
}

fn mapping_preflight_targets(mapping: &config::Mapping) -> Vec<(String, u16)> {
    let mut targets = BTreeSet::new();
    targets.insert((mapping.host.clone(), mapping.port));
    if mapping.mode == config::MappingMode::Http {
        for route in &mapping.routes {
            targets.insert((route.target_host.clone(), route.target_port));
        }
    }
    targets.into_iter().collect()
}

fn is_literal_loopback_target(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(tunnel::is_loopback_address)
}

fn literal_loopback_acknowledgement_error(mapping: &config::Mapping) -> Option<String> {
    if mapping.allow_loopback_target {
        return None;
    }
    mapping_preflight_targets(mapping)
        .into_iter()
        .find(|(host, _)| is_literal_loopback_target(host))
        .map(|(host, port)| format!("{host}:{port} 是字面 loopback 目标，需要显式确认风险"))
}

async fn require_mapping_loopback_acknowledgement(
    st: &AppState,
    mapping: &config::Mapping,
) -> Result<(), (StatusCode, String)> {
    // An offline peer cannot resolve names for preflight, but literal loopback targets are
    // already unambiguous. Enforce their acknowledgement locally before accepting a mapping;
    // nonliteral host names remain an expose-side resolver decision so NAT hairpin routes stay
    // valid and arbitrary multi-machine cycles are not misclassified.
    if let Some(error) = literal_loopback_acknowledgement_error(mapping) {
        return Err((StatusCode::BAD_REQUEST, error));
    }
    // Offline configuration remains supported. Once a peer is reachable, its own resolver is
    // authoritative; every live tunnel still enforces the same rule before dialing.
    let peer_id = st
        .peers
        .resolve_mapping_peer_id(&mapping.peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let peer = st
        .peers
        .peer_config(&peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    if peer.node_id.trim().is_empty() {
        return Ok(());
    }
    let link = st
        .peers
        .acquire_link(&peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let kind = match mapping.mode {
        config::MappingMode::Udp => proto::TunnelKind::Udp,
        _ => proto::TunnelKind::Tcp,
    };
    let result = async {
        for (host, port) in mapping_preflight_targets(mapping) {
            let request = proto::OpenRequest {
                token: link.token().await,
                host: host.clone(),
                port,
                kind,
                register: false,
                preflight: true,
                allow_loopback_target: mapping.allow_loopback_target,
            };
            if let Ok(Ok(proto::OpenStatus::LoopRisk(message))) = tokio::time::timeout(
                Duration::from_secs(8),
                open_preflight_with_retry(&link, &request),
            )
            .await
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("{host}:{port} 需要显式确认 loopback 风险：{message}"),
                ));
            }
        }
        Ok(())
    }
    .await;
    st.peers.release_link(&peer_id).await;
    result
}

/// POST /api/mappings/preflight --- transiently verifies the same remote path a
/// mapping will use, without creating a listener or persisting configuration.
async fn preflight(
    State(st): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<PreflightResult>, (StatusCode, String)> {
    let peer_id = st
        .peers
        .resolve_mapping_peer_id(body.peer_id.as_deref().unwrap_or_default())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mapping = config::Mapping {
        peer_id,
        allow_loopback_target: loopback_acknowledged(
            body.acknowledge_loop_risk,
            body.allow_loopback_target,
            false,
        ),
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

    let peer_id = st
        .peers
        .resolve_mapping_peer_id(&mapping.peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let peer = st
        .peers
        .peer_config(&peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let configured = !peer.node_id.trim().is_empty();
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
        (
            PreflightCheck {
                ok: false,
                detail: "请先解决本地监听地址或端口占用问题".into(),
            },
            None,
        )
    } else if !configured {
        (
            PreflightCheck {
                ok: false,
                detail: "需要有效凭证后才能验证目标服务".into(),
            },
            None,
        )
    } else {
        let link = st
            .peers
            .acquire_link(&peer_id)
            .await
            .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
        // 预检按映射模式选对应隧道类型：udp 校验 UDP 目标可达，其余（含 http 网关）走 tcp。
        let kind = match mapping.mode {
            config::MappingMode::Udp => proto::TunnelKind::Udp,
            _ => proto::TunnelKind::Tcp,
        };
        let request = proto::OpenRequest {
            token: link.token().await,
            host: mapping.host.clone(),
            port: mapping.port,
            kind,
            register: false,
            preflight: true,
            allow_loopback_target: mapping.allow_loopback_target,
        };
        let result = match tokio::time::timeout(
            Duration::from_secs(8),
            open_preflight_with_retry(&link, &request),
        )
        .await
        {
            Ok(Ok(status)) => target_preflight_check(status, &mapping.host, mapping.port),
            Ok(Err(error)) => (
                PreflightCheck {
                    ok: false,
                    detail: diagnostic_reason(&error),
                },
                None,
            ),
            Err(_) => (
                PreflightCheck {
                    ok: false,
                    detail: "验证目标服务超时，请检查网络、白名单和目标端口".into(),
                },
                None,
            ),
        };
        st.peers.release_link(&peer_id).await;
        result
    };
    checks.insert("target", target.0);
    let ready = checks.values().all(|check| check.ok);
    Ok(Json(PreflightResult {
        ready,
        loop_risk: target.1,
        checks,
    }))
}

async fn create(
    State(st): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<config::Mapping>, (StatusCode, String)> {
    let _operation = lock_mapping_operation(&st).await;
    let peer_id = st
        .peers
        .resolve_mapping_peer_id(body.peer_id.as_deref().unwrap_or_default())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mapping = config::Mapping {
        peer_id,
        allow_loopback_target: loopback_acknowledged(
            body.acknowledge_loop_risk,
            body.allow_loopback_target,
            false,
        ),
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
    require_mapping_loopback_acknowledgement(&st, &mapping).await?;
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
    let mut unpublished_handle = Some(handle);
    let publish_error = {
        let mut g = st.inner.lock().await;
        // 双检：加锁间隙可能被其他请求抢先插入或触达上限。
        if g.mappings.contains_key(&mapping.local) {
            Some((
                StatusCode::CONFLICT,
                format!("{} 已存在映射", mapping.local),
            ))
        } else if st.max_mappings > 0 && g.mappings.len() >= st.max_mappings {
            Some((
                StatusCode::TOO_MANY_REQUESTS,
                format!("映射数量已达上限 {}", st.max_mappings),
            ))
        } else {
            g.mappings.insert(
                mapping.local.clone(),
                unpublished_handle
                    .take()
                    .expect("unpublished mapping handle is available"),
            );
            None
        }
    };
    if let Some(error) = publish_error {
        stop_mapping(
            &st,
            unpublished_handle.expect("unpublished mapping handle is retained on publish failure"),
        )
        .await;
        return Err(error);
    }
    if let Err(error) = persist_peer_state(&st).await {
        let handle = st.inner.lock().await.mappings.remove(&mapping.local);
        if let Some(handle) = handle {
            stop_mapping(&st, handle).await;
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存映射失败: {error}"),
        ));
    }
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
        peer_id: None,
    }
}

/// 启动一条映射的本地监听；返回运行期把手（含取消令牌）。
/// 停用的映射不绑定本地端口，只登记为 disabled 状态，随时可再启用。
/// 按 mode 分派：tcp / http 走 TCP 监听（http 额外按 Host 头选后端），udp 走 UDP socket。
async fn start_mapping_owned(
    st: &AppState,
    mut mapping: config::Mapping,
) -> Result<MappingHandle, (StatusCode, String)> {
    mapping.peer_id = st
        .peers
        .resolve_mapping_peer_id(&mapping.peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    if !mapping.enabled {
        return Ok(disabled_handle(mapping));
    }
    let link = st
        .peers
        .acquire_link(&mapping.peer_id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    st.peers
        .watch_link(
            mapping.peer_id.clone(),
            link.clone(),
            st.metrics.clone(),
            st.events.clone(),
        )
        .await;
    let peer_id = mapping.peer_id.clone();
    let result = match mapping.mode {
        config::MappingMode::Udp => start_udp_mapping(st, mapping, link, peer_id.clone()).await,
        config::MappingMode::Tcp | config::MappingMode::Http => {
            start_tcp_mapping(st, mapping, link, peer_id.clone()).await
        }
    };
    if result.is_err() {
        st.peers.release_link(&peer_id).await;
    }
    result
}

/// A peer change cannot reuse a listener task because that task owns the Link it captured.
/// Stop the old listener before binding the replacement on the same local address.
async fn rebuild_mapping_for_peer(
    st: &AppState,
    old: MappingHandle,
    mapping: config::Mapping,
) -> Result<MappingHandle, (StatusCode, String)> {
    stop_mapping(st, old).await;
    start_mapping_owned(st, mapping).await
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

/// 映射监听在非回环地址时给出告警：这会把本地服务直接暴露给同网段的其他主机，
/// 与“只通过隧道访问”的默认预期不同。
fn warn_if_public_bind(local: &str) {
    let host = local.rsplit_once(':').map(|(h, _)| h).unwrap_or(local);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !ip.is_loopback()
    {
        tracing::warn!(
            listen = %local,
            "映射监听在非回环地址：局域网内其他主机可绕过隧道直接访问该端口"
        );
    }
}

/// TCP / HTTP 网关映射：绑定本地 TCP 端口，每个连接复用到 B 的隧道。
/// http 模式下先窥探 Host 头选后端并把读走的头重放给后端；tcp 模式 prefix 为空。
async fn start_tcp_mapping(
    st: &AppState,
    mapping: config::Mapping,
    link: Link,
    peer_id: String,
) -> Result<MappingHandle, (StatusCode, String)> {
    let listener = (st.mapping_listener)(mapping.local.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("绑定 {} 失败: {e}", mapping.local),
            )
        })?;
    warn_if_public_bind(&mapping.local);
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
        // accept() 的瞬时错误（EMFILE 等）不应让整条映射永久下线；
        // 连续错误时指数退避，成功一次就复位。只有取消才退出循环。
        let mut accept_errors: u32 = 0;
        loop {
            let accepted = tokio::select! {
                // 映射被删除或进程退出：停止接受新连接并 drain（取消所有子任务）。
                _ = cancel_task.cancelled() => break,
                r = listener.accept() => r,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    accept_errors = 0;
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
                        let (mode, host, port, routes, allow_loopback_target) = {
                            let m = mapping.read().await;
                            (
                                m.mode,
                                m.host.clone(),
                                m.port,
                                m.routes.clone(),
                                m.allow_loopback_target,
                            )
                        };
                        // HTTP 网关：窥探 Host 头选后端，读走的头随后重放给后端。
                        let mut tcp = tcp;
                        let (target_host, target_port, prefix) = if mode
                            == config::MappingMode::Http
                        {
                            match tokio::time::timeout(
                                Duration::from_secs(10),
                                peek_http_head(&mut tcp),
                            )
                            .await
                            {
                                Ok(Ok((buf, host_header))) => {
                                    let snapshot = config::Mapping {
                                        peer_id: String::new(),
                                        allow_loopback_target,
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
                                Ok(Err(e)) => {
                                    Metrics::inc(&metrics.tunnels_failed);
                                    stats
                                        .record_failure(&anyhow::anyhow!("读取 HTTP 头失败: {e}"))
                                        .await;
                                    return;
                                }
                                Err(_) => {
                                    Metrics::inc(&metrics.tunnels_failed);
                                    stats
                                        .record_failure(&anyhow::anyhow!(
                                            "读取 HTTP 头超时（10 秒内未收到完整请求头）"
                                        ))
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
                            preflight: false,
                            allow_loopback_target,
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
                    accept_errors = accept_errors.saturating_add(1);
                    let backoff =
                        Duration::from_millis(100u64.saturating_mul(1u64 << accept_errors.min(5)));
                    tracing::error!(
                        error = %e,
                        local = %local,
                        consecutive = accept_errors,
                        backoff_ms = backoff.as_millis(),
                        "本地监听 accept 失败，退避后重试"
                    );
                    tokio::select! {
                        _ = cancel_task.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
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
        peer_id: Some(peer_id),
    })
}

/// UDP 映射：绑定本地 UDP socket，按来源地址维护会话，每个来源复用一条到 B 的 UDP 隧道流。
/// 会话空闲超时后回收；本地无连接语义，因此用来源地址做键。
async fn start_udp_mapping(
    st: &AppState,
    mapping: config::Mapping,
    link: Link,
    peer_id: String,
) -> Result<MappingHandle, (StatusCode, String)> {
    let socket = tokio::net::UdpSocket::bind(&mapping.local)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("绑定 UDP {} 失败: {e}", mapping.local),
            )
        })?;
    warn_if_public_bind(&mapping.local);
    let socket = Arc::new(socket);
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
                let (host, port, allow_loopback_target) = {
                    let m = mapping.read().await;
                    (m.host.clone(), m.port, m.allow_loopback_target)
                };
                let req = proto::OpenRequest {
                    token: link.token().await,
                    host,
                    port,
                    kind: proto::TunnelKind::Udp,
                    register: false,
                    preflight: false,
                    allow_loopback_target,
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
        peer_id: Some(peer_id),
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

async fn remove(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let _operation = lock_mapping_operation(&st).await;
    let handle = st.inner.lock().await.mappings.remove(&id);
    let Some(handle) = handle else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Keep the listener alive until the deletion has reached disk. This makes a failed save a
    // pure in-memory rollback instead of a best-effort attempt to rebind its address.
    if let Err(error) = persist_peer_state(&st).await {
        st.inner.lock().await.mappings.insert(id.clone(), handle);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存映射失败: {error}"),
        )
            .into_response();
    }
    stop_mapping(&st, handle).await;
    st.events
        .push("info", "mapping", format!("已断开映射 {id}"));
    StatusCode::NO_CONTENT.into_response()
}

/// PUT /api/mappings/{id} —— 就地编辑一条映射。
/// 仅改目标（host/port）时复用原监听 socket、不重绑端口，已建立的隧道不受影响，
/// 后续新连接立即用新目标。改本地地址时先绑定新地址再停旧监听，失败则原样保留。
async fn update(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Result<Json<config::Mapping>, (StatusCode, String)> {
    let _operation = lock_mapping_operation(&st).await;
    let g = st.inner.lock().await;
    let existing = g
        .mappings
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, format!("{id} 不存在映射")))?;
    // 编辑表单不改变启用状态：省略 enabled 时沿用原值，启用/停用走专门的 toggle 接口。
    // name 同理：省略时沿用原名称，避免编辑目标时把名称清空。
    let old_mapping = existing.mapping.read().await.clone();
    let was_peer_id = old_mapping.peer_id.clone();
    let was_allow_loopback_target = old_mapping.allow_loopback_target;
    let was_enabled = old_mapping.enabled;
    let was_name = old_mapping.name.clone();
    let was_mode = old_mapping.mode;
    let was_routes = old_mapping.routes.clone();
    let peer_id = st
        .peers
        .resolve_mapping_peer_id(body.peer_id.as_deref().unwrap_or(&was_peer_id))
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mapping = config::Mapping {
        peer_id,
        allow_loopback_target: loopback_acknowledged(
            body.acknowledge_loop_risk,
            body.allow_loopback_target,
            was_allow_loopback_target,
        ),
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
    require_mapping_loopback_acknowledgement(&st, &mapping).await?;

    // 本地地址、启用状态、传输类型与对端都没变：复用原把手，原子更新目标，无重绑竞争。
    // UDP 与 TCP/HTTP 用的是不同 socket 与接受循环，必须重绑；漏判会把 UDP 映射
    // 的配置改成 TCP 却继续跑旧的 UDP 监听。
    let same_socket_kind = matches!(mapping.mode, config::MappingMode::Udp)
        == matches!(was_mode, config::MappingMode::Udp);
    if mapping.local == id
        && mapping.enabled == was_enabled
        && mapping.peer_id == was_peer_id
        && same_socket_kind
    {
        let handle = g.mappings.get(&id).expect("已确认存在");
        let mapping_state = handle.mapping.clone();
        *mapping_state.write().await = mapping.clone();
        drop(g);
        if let Err(error) = persist_peer_state(&st).await {
            *mapping_state.write().await = old_mapping;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存映射失败: {error}"),
            ));
        }
        return Ok(Json(mapping));
    }

    // 改本地地址：新地址不能与其他映射冲突。
    if mapping.local != id && g.mappings.contains_key(&mapping.local) {
        return Err((
            StatusCode::CONFLICT,
            format!("{} 已存在映射", mapping.local),
        ));
    }
    drop(g);

    // A same-address peer switch must recreate the listener because its task captured the old
    // peer Link. Rebuild failures must also restore that old listener before returning.
    if mapping.local == id && mapping.enabled && was_enabled && mapping.peer_id != was_peer_id {
        let old = st
            .inner
            .lock()
            .await
            .mappings
            .remove(&id)
            .expect("已确认存在");
        let replacement = match rebuild_mapping_for_peer(&st, old, mapping.clone()).await {
            Ok(handle) => handle,
            Err(error) => {
                match start_mapping_owned(&st, old_mapping.clone()).await {
                    Ok(restored) => {
                        st.inner.lock().await.mappings.insert(id, restored);
                    }
                    Err((_, rollback_error)) => tracing::error!(
                        error = %rollback_error,
                        "对端切换重建失败后无法恢复原映射"
                    ),
                }
                return Err(error);
            }
        };
        st.inner
            .lock()
            .await
            .mappings
            .insert(mapping.local.clone(), replacement);
        if let Err(error) = persist_peer_state(&st).await {
            let replacement = st.inner.lock().await.mappings.remove(&mapping.local);
            if let Some(replacement) = replacement {
                stop_mapping(&st, replacement).await;
            }
            match start_mapping_owned(&st, old_mapping).await {
                Ok(restored) => {
                    st.inner.lock().await.mappings.insert(id, restored);
                }
                Err((_, rollback_error)) => tracing::error!(
                    error = %rollback_error,
                    "对端切换保存失败后无法恢复原映射"
                ),
            }
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存映射失败: {error}"),
            ));
        }
        return Ok(Json(mapping));
    }

    // 先按新参数（含启用态）建把手；成功后再停旧的，避免旧地址提前释放又绑不上新地址。
    let handle = start_mapping_owned(&st, mapping.clone()).await?;
    let old = {
        let mut g = st.inner.lock().await;
        let old = g.mappings.remove(&id).expect("已确认存在");
        g.mappings.insert(mapping.local.clone(), handle);
        old
    };
    if let Err(error) = persist_peer_state(&st).await {
        let replacement = st.inner.lock().await.mappings.remove(&mapping.local);
        st.inner.lock().await.mappings.insert(id, old);
        if let Some(replacement) = replacement {
            stop_mapping(&st, replacement).await;
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存映射失败: {error}"),
        ));
    }
    stop_mapping(&st, old).await;
    Ok(Json(mapping))
}

/// POST /api/mappings/{id}/toggle —— 启用/停用一条映射。
/// 停用释放本地端口并 drain 在途连接；启用重新绑定端口。地址不变，仅切换运行态。
async fn toggle(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<config::Mapping>, (StatusCode, String)> {
    let _operation = lock_mapping_operation(&st).await;
    let mut g = st.inner.lock().await;
    let existing = g
        .mappings
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, format!("{id} 不存在映射")))?;
    let mut mapping = existing.mapping.read().await.clone();
    let was_enabled = mapping.enabled;
    mapping.enabled = !mapping.enabled;
    if !was_enabled && mapping.enabled {
        require_mapping_loopback_acknowledgement(&st, &mapping).await?;
    }
    // 启用时按当前地址重新绑定；停用时换成不占端口的把手。任一路径失败则保持原样。
    let handle = start_mapping_owned(&st, mapping.clone()).await?;
    let old = g.mappings.remove(&id).expect("已确认存在");
    g.mappings.insert(mapping.local.clone(), handle);
    drop(g);
    if let Err(error) = persist_peer_state(&st).await {
        let replacement = st.inner.lock().await.mappings.remove(&mapping.local);
        st.inner.lock().await.mappings.insert(id, old);
        if let Some(replacement) = replacement {
            stop_mapping(&st, replacement).await;
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存映射失败: {error}"),
        ));
    }
    stop_mapping(&st, old).await;
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
) -> Result<Json<ToggleAllResult>, (StatusCode, String)> {
    let _operation = lock_mapping_operation(&st).await;
    let target = body.enabled;
    // 先取出需要切换的 local 列表，避免持锁期间跨 await 重建监听。
    let (to_switch, total): (Vec<String>, usize) = {
        let g = st.inner.lock().await;
        let mut locals = Vec::new();
        for (local, handle) in g.mappings.iter() {
            if handle.mapping.read().await.enabled != target {
                locals.push(local.clone());
            }
        }
        (locals, g.mappings.len())
    };
    // 两次加锁之间映射可能被并发删除；用 saturating 避免 len - n 下溢 panic。
    let unchanged = total.saturating_sub(to_switch.len());
    let mut changed = 0usize;
    let mut failed = 0usize;
    let mut replaced = Vec::new();
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
        let was_enabled = mapping.enabled;
        mapping.enabled = target;
        if !was_enabled
            && mapping.enabled
            && require_mapping_loopback_acknowledgement(&st, &mapping)
                .await
                .is_err()
        {
            drop(g);
            failed += 1;
            continue;
        }
        match start_mapping_owned(&st, mapping.clone()).await {
            Ok(handle) => {
                let old = g.mappings.remove(&id).expect("已确认存在");
                g.mappings.insert(mapping.local.clone(), handle);
                drop(g);
                // Keep the previous handle alive until the complete batch is durably saved.
                // In particular, disabling a mapping must not release its listener before a
                // disk error can restore it.
                replaced.push((id, mapping.local.clone(), old));
                changed += 1;
            }
            Err(_) => {
                drop(g);
                failed += 1;
            }
        }
    }
    if changed > 0 {
        if let Err(error) = persist_peer_state(&st).await {
            let replacements = {
                let mut g = st.inner.lock().await;
                let mut replacements = Vec::with_capacity(replaced.len());
                for (old_id, new_id, old) in replaced {
                    if let Some(new) = g.mappings.remove(&new_id) {
                        replacements.push(new);
                    }
                    g.mappings.insert(old_id, old);
                }
                replacements
            };
            for replacement in replacements {
                stop_mapping(&st, replacement).await;
            }
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存映射失败: {error}"),
            ));
        }
        for (_, _, old) in replaced {
            stop_mapping(&st, old).await;
        }
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
    Ok(Json(ToggleAllResult {
        enabled: target,
        changed,
        unchanged,
        failed,
    }))
}

/// 去掉 Host/Origin 里的端口；IPv6 字面量 `[::1]:8088` 返回 `::1`。
fn host_without_port(value: &str) -> &str {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &rest[..end];
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => value,
    }
}

/// 管理页允许的 Host：回环名/地址、web_bind 的地址，以及显式配置的反代域名。
/// 这是 DNS rebinding 的唯一可靠防线——恶意页面可以让自己的域名解析到 127.0.0.1，
/// 但浏览器发出的 Host 仍是攻击者域名。
fn host_allowed(value: &str, st: &AppState) -> bool {
    let host = host_without_port(value).to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    // TLS 由本进程直接终止时，浏览器会对证书域名做校验，HTTP 层的 Host 校验可放宽，
    // 以免破坏已有的远程 HTTPS 管理部署。
    if !st.web_tls_cert.is_empty() {
        return true;
    }
    if let Some((bind_host, _)) = st.web_bind.rsplit_once(':') {
        let bind_host = bind_host.trim_matches(['[', ']']);
        if !matches!(bind_host, "" | "0.0.0.0" | "::") && host.eq_ignore_ascii_case(bind_host) {
            return true;
        }
    }
    st.web_allowed_hosts
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed.trim().trim_end_matches('.')))
}

fn origin_allowed(origin: &str, st: &AppState) -> bool {
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    host_allowed(authority, st)
}

fn forbidden(message: &'static str) -> Response {
    (StatusCode::FORBIDDEN, message).into_response()
}

/// 管理服务的浏览器侧防护：
/// - Host 白名单：阻断 DNS rebinding（恶意网页把自己的域名解析到 127.0.0.1 后读写管理 API）；
/// - 跨站写请求：对 Origin / Sec-Fetch-Site 做二次校验，阻断 CSRF；
/// - 统一安全响应头；`/api/*` 一律 `no-store`，避免令牌与配置进入浏览器缓存。
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    if let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        && !host_allowed(host, &st)
    {
        return forbidden("Host 不在管理页允许列表内（DNS rebinding 防护）");
    }
    if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            && !origin_allowed(origin, &st)
        {
            return forbidden("跨站写请求被拒绝（Origin 校验失败）");
        }
        if let Some(site) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            && site.eq_ignore_ascii_case("cross-site")
        {
            return forbidden("跨站写请求被拒绝（Sec-Fetch-Site: cross-site）");
        }
    }

    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; \
             style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
             font-src 'self' https://fonts.gstatic.com; \
             script-src 'self' 'unsafe-inline'; connect-src 'self'; \
             object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    if path.starts_with("/api/") {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    response
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/powermap-logo.svg", get(powermap_logo))
        .route("/metrics", get(metrics_handler))
        .route("/api/health", get(health))
        .route("/api/runtime", get(runtime_info))
        .route("/api/status", get(status))
        .route("/api/diagnostics", get(diagnostics))
        .route("/api/onboarding", get(onboarding))
        .route("/api/local-services", get(local_services))
        .route("/api/mapping-templates", get(mapping_templates))
        .route("/api/mapping-health", get(mapping_health))
        .route("/api/diagnostic-report", get(diagnostic_report))
        .route("/api/mappings/port-suggestions", get(port_suggestions))
        .route("/api/stats", get(stats))
        .route("/api/events", get(events))
        .route("/api/mappings/preflight", post(preflight))
        .route("/api/mappings", get(list).post(create))
        .route("/api/mappings/{id}", put(update).delete(remove))
        .route("/api/mappings/{id}/toggle", post(toggle))
        .route("/api/mappings/toggle-all", post(toggle_all))
        .route("/api/peers", get(list_peers).post(create_peer))
        .route("/api/peers/{id}", put(update_peer).delete(delete_peer))
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
        .route("/api/relay/probe", get(probe_relays))
        .route("/api/relay", get(get_relay).put(set_relay))
        .route("/api/reverse", get(get_reverse).put(set_reverse))
        .route("/api/export", get(export_config))
        .route("/api/import", post(import_config))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
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
    Json(mut body): Json<ReverseConfig>,
) -> Result<Json<ReverseConfig>, (StatusCode, String)> {
    // 与 config::AConfig::validate 共用同一套格式校验（空集=拒绝的语义由运行期策略负责）。
    config::validate_allowlist(
        "reverse_allow_networks",
        "reverse_allow_ports",
        &body.allow_networks,
        &body.allow_ports,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if body.enabled {
        body.peer_id = st
            .peers
            .resolve_reverse_peer_id(&body.peer_id)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    }
    let previous = std::mem::replace(&mut *st.reverse.write().await, body.clone());
    if let Err(error) = persist_peer_state(&st).await {
        *st.reverse.write().await = previous;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存反向映射策略失败: {error}"),
        ));
    }
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

async fn build_config(st: &AppState) -> Result<config::AConfig, String> {
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
        let mut mapping = mapping.read().await.clone();
        mapping.peer_id = st.peers.resolve_mapping_peer_id(&mapping.peer_id).await?;
        mappings.push(mapping);
    }
    let mut domain_mappings = Vec::new();
    {
        let domains = st.domains.lock().await;
        domain_mappings.reserve(domains.mappings.len());
        for handle in domains.mappings.values() {
            let mut mapping = handle.mapping.read().await.clone();
            mapping.peer_id = st.peers.resolve_mapping_peer_id(&mapping.peer_id).await?;
            domain_mappings.push(mapping);
        }
    }
    domain_mappings.sort_by(|a, b| a.domain.cmp(&b.domain));
    let peers = st.peers.peer_configs().await;
    let (node_id, token, published_targets) = peers
        .iter()
        .find(|peer| peer.name == "默认对端")
        .map(|peer| {
            (
                peer.node_id.clone(),
                peer.token.clone(),
                peer.published_targets.clone(),
            )
        })
        .unwrap_or_else(|| (String::new(), String::new(), Vec::new()));
    let reverse = st.reverse.read().await.clone();
    Ok(config::AConfig {
        node_id,
        token,
        relay: config::RelaySettings::default(),
        peers,
        web_bind: st.web_bind.clone(),
        web_token: st.web_token.clone(),
        web_tls_cert: st.web_tls_cert.clone(),
        web_tls_key: st.web_tls_key.clone(),
        web_allowed_hosts: st.web_allowed_hosts.clone(),
        max_mappings: st.max_mappings,
        max_conns_per_mapping: st.max_conns_per_mapping,
        mappings,
        domain_mappings,
        published_targets,
        reverse_enabled: reverse.enabled,
        reverse_peer_id: reverse.peer_id,
        reverse_allow_networks: reverse.allow_networks,
        reverse_allow_ports: reverse.allow_ports,
    })
}

/// Copy the state owned by the legacy single-peer runtime into the only peer it can identify.
/// A persisted peer model with any other shape must remain untouched until the peer-aware runtime
/// is available.
#[derive(Clone, Copy)]
struct LegacyRuntimeSync {
    credentials: bool,
    relay: bool,
}

impl LegacyRuntimeSync {
    const NONE: Self = Self {
        credentials: false,
        relay: false,
    };
    const RELAY: Self = Self {
        credentials: false,
        relay: true,
    };
}

fn merge_legacy_runtime_access(
    mut runtime: config::AConfig,
    persisted: Option<&config::AConfig>,
    runtime_relay: &config::RelaySettings,
    sync: LegacyRuntimeSync,
) -> config::AConfig {
    let Some(persisted) = persisted.filter(|access| !access.peers.is_empty()) else {
        runtime.relay = runtime_relay.clone();
        return runtime;
    };

    runtime.peers = persisted.peers.clone();
    if let Some(peer_id) = persisted.legacy_default_peer_id() {
        let peer_id = peer_id.to_owned();
        // The legacy runtime predates mapping ownership. Once its first save creates the
        // migrated peer, retain that ownership in subsequent runtime-only saves.
        for mapping in &mut runtime.mappings {
            if mapping.peer_id.trim().is_empty() {
                mapping.peer_id = peer_id.clone();
            }
        }
        for mapping in &mut runtime.domain_mappings {
            if mapping.peer_id.trim().is_empty() {
                mapping.peer_id = peer_id.clone();
            }
        }
        if let Some(peer) = runtime.peers.iter_mut().find(|peer| peer.id == peer_id) {
            if sync.credentials {
                peer.node_id = runtime.node_id.clone();
                peer.token = runtime.token.clone();
                peer.published_targets = runtime.published_targets.clone();
            }
            if sync.relay {
                peer.relay = runtime_relay.clone();
            }
        }
    }
    runtime.node_id.clear();
    runtime.token.clear();
    runtime.published_targets.clear();
    runtime.relay = config::RelaySettings::default();
    runtime
}

#[cfg(test)]
fn legacy_default_peer_for_route(
    access: Option<&config::AConfig>,
) -> Result<Option<String>, String> {
    let Some(access) = access else {
        return Ok(None);
    };
    if access.peers.is_empty() {
        return Ok(None);
    }
    access
        .legacy_default_peer_id()
        .map(str::to_owned)
        .map_or_else(
            || {
                Err(
                    "当前配置不是单一的“默认对端”；旧版接口无法安全选择对端，请使用对端专用 API"
                        .into(),
                )
            },
            |peer_id| Ok(Some(peer_id)),
        )
}

async fn legacy_default_peer_id_for_route(st: &AppState) -> Result<String, (StatusCode, String)> {
    st.peers
        .legacy_default_peer_id()
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))
}

/// Mapping routes have no peer selector, so they may operate only before migration or against
/// the one migrated default peer. Run this before acquiring runtime mapping state.
async fn ensure_legacy_mapping_mutation_compatible(
    st: &AppState,
) -> Result<(), (StatusCode, String)> {
    legacy_default_peer_id_for_route(st).await.map(|_| ())
}

#[cfg(test)]
async fn persist_config(st: &AppState) -> Result<(), String> {
    persist_config_with_runtime_sync(st, LegacyRuntimeSync::NONE).await
}

async fn persist_config_with_runtime_sync(
    st: &AppState,
    sync: LegacyRuntimeSync,
) -> Result<(), String> {
    let _save = st.config_save.lock().await;
    let runtime_relay = st
        .peers
        .legacy_default_relay_settings()
        .await
        .unwrap_or_default();
    let mut cfg = config::load_config(&st.config_path, None)
        .map_err(|error| format!("读取配置失败: {error}"))?
        .config;
    let access = merge_legacy_runtime_access(
        build_config(st).await?,
        cfg.access.as_ref(),
        &runtime_relay,
        sync,
    );
    cfg.access = Some(access);
    cfg.normalize_access_peers()?;
    cfg.validate()?;
    config::save(&st.config_path, &cfg).map_err(|error| format!("写入配置失败: {error}"))
}

/// 测试辅助：持久化完整的运行期 peer 模型，而不是走单默认 peer 的兼容桥。
/// 失败必须让调用方知道：只打日志会让管理页在「已生效但没写盘」时仍显示成功。
#[cfg(test)]
async fn save_config(st: &AppState) -> Result<(), String> {
    persist_peer_state(st).await
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
    relay: config::RelaySettings,
    restart_required: bool,
}

#[derive(Serialize)]
struct RelaySettingsView {
    #[serde(flatten)]
    relay: config::RelaySettings,
    restart_required: bool,
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
async fn get_credential(
    State(st): State<AppState>,
) -> Result<Json<CredentialView>, (StatusCode, String)> {
    let peer = st
        .peers
        .legacy_default_peer_config()
        .await
        .map_err(|error| (StatusCode::CONFLICT, error))?;
    let restart_required = match st.peers.legacy_default_cached_link().await {
        Ok(Some(link)) => link.relay_restart_required().await,
        _ => false,
    };
    Ok(Json(CredentialView {
        configured: !peer.node_id.trim().is_empty(),
        node_id: peer.node_id,
        token: peer.token,
        token_hidden: false,
        published_targets: peer.published_targets,
        relay: peer.relay,
        restart_required,
    }))
}

/// GET /api/relay --- the persisted relay configuration and whether an Endpoint restart is due.
async fn get_relay(
    State(st): State<AppState>,
) -> Result<Json<RelaySettingsView>, (StatusCode, String)> {
    let peer = st
        .peers
        .legacy_default_peer_config()
        .await
        .map_err(|error| (StatusCode::CONFLICT, error))?;
    let restart_required = match st.peers.legacy_default_cached_link().await {
        Ok(Some(link)) => link.relay_restart_required().await,
        _ => false,
    };
    Ok(Json(RelaySettingsView {
        relay: peer.relay,
        restart_required,
    }))
}

/// A bounded control-plane probe for each configured private relay. This uses iroh-relay's
/// `/ping` endpoint and measures DNS/TLS/HTTP setup only; it does not create a tunnel.
#[derive(Serialize)]
struct RelayProbeReport {
    relays: Vec<RelayProbeResult>,
}

#[derive(Serialize)]
struct RelayProbeResult {
    url: String,
    reachable: bool,
    latency_ms: Option<u64>,
    http_status: Option<u16>,
    error: Option<&'static str>,
}

async fn probe_relays(
    State(st): State<AppState>,
) -> Result<Json<RelayProbeReport>, (StatusCode, String)> {
    ensure_legacy_mapping_mutation_compatible(&st).await?;
    let settings = st
        .peers
        .legacy_default_peer_config()
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?
        .relay;
    Ok(Json(RelayProbeReport {
        relays: probe_relay_entries(settings.relays).await,
    }))
}

async fn probe_relay_entries(entries: Vec<config::RelayEntry>) -> Vec<RelayProbeResult> {
    if entries.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .user_agent(format!(
            "powermap/{} relay-probe",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return entries
                .into_iter()
                .map(|entry| RelayProbeResult {
                    url: entry.url,
                    reachable: false,
                    latency_ms: None,
                    http_status: None,
                    error: Some("无法初始化探测器"),
                })
                .collect();
        }
    };

    let mut probes = JoinSet::new();
    for (index, entry) in entries.into_iter().enumerate() {
        let client = client.clone();
        probes.spawn(async move { (index, probe_relay(&client, entry).await) });
    }

    let mut results = Vec::new();
    while let Some(result) = probes.join_next().await {
        if let Ok(result) = result {
            results.push(result);
        }
    }
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

async fn probe_relay(client: &reqwest::Client, entry: config::RelayEntry) -> RelayProbeResult {
    let request = match relay_probe_request(client, &entry) {
        Some(request) => request,
        None => {
            return RelayProbeResult {
                url: entry.url,
                reachable: false,
                latency_ms: None,
                http_status: None,
                error: Some("中继地址无效"),
            };
        }
    };
    let started = Instant::now();

    match request.send().await {
        Ok(response) => {
            let status = response.status();
            RelayProbeResult {
                url: entry.url,
                reachable: status.is_success(),
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                http_status: Some(status.as_u16()),
                error: (!status.is_success()).then_some("中继未返回成功状态"),
            }
        }
        Err(error) => RelayProbeResult {
            url: entry.url,
            reachable: false,
            latency_ms: None,
            http_status: None,
            error: Some(if error.is_timeout() {
                "连接超时"
            } else if error.is_connect() {
                "无法建立 HTTPS 连接"
            } else {
                "中继探测失败"
            }),
        },
    }
}

fn relay_probe_url(value: &str) -> Option<String> {
    value
        .parse::<RelayUrl>()
        .ok()?
        .join("/ping")
        .ok()
        .map(|url| url.to_string())
}

/// `/ping` is public control-plane health. It intentionally does not receive relay admission
/// credentials, so a latency check cannot disclose a token to the configured destination.
fn relay_probe_request(
    client: &reqwest::Client,
    entry: &config::RelayEntry,
) -> Option<reqwest::RequestBuilder> {
    relay_probe_url(&entry.url).map(|target| client.get(target))
}

/// PUT /api/relay --- validate, persist, and apply a replacement RelayMap without restarting.
async fn set_relay(
    State(st): State<AppState>,
    Json(relay): Json<config::RelaySettings>,
) -> Result<Json<RelaySettingsView>, (StatusCode, String)> {
    let _peer_id = legacy_default_peer_id_for_route(&st).await?;
    let _update = st.relay_update.lock().await;
    let link = st
        .peers
        .legacy_default_link()
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let previous = link.relay_settings().await;
    let apply = link
        .set_relay(relay.clone())
        .await
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    if let Err(error) = persist_config_with_runtime_sync(&st, LegacyRuntimeSync::RELAY).await {
        if let Err(rollback_error) = link.set_relay(previous).await {
            tracing::error!(error = %rollback_error, "relay 配置持久化失败后无法回滚运行时设置");
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存 relay 配置失败: {error}"),
        ));
    }
    st.events.push(
        "info",
        "relay",
        if apply.restart_required {
            "已保存 relay 配置；强制中继变更将在重启后生效"
        } else {
            "已更新 relay 配置，后续连接将使用新节点"
        },
    );
    Ok(Json(RelaySettingsView {
        relay,
        restart_required: apply.restart_required,
    }))
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
    let _peer_id = legacy_default_peer_id_for_route(&st).await?;
    // A shared credential may replace the relay settings. Keep it, the credential, and
    // persistence as one operation so a write error cannot leave either change memory-only.
    let _relay_update = st.relay_update.lock().await;
    let link = st
        .peers
        .legacy_default_link()
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let previous_creds = link.creds.read().await.clone();
    let previous_relay = link.relay_settings().await;
    let replaces_relay = cred.relay.is_some();
    let apply = if let Some(relay) = cred.relay.clone() {
        link.set_relay(relay)
            .await
            .map_err(|message| (StatusCode::BAD_REQUEST, message))?
    } else {
        RelayApply {
            restart_required: link.relay_restart_required().await,
        }
    };
    if apply.restart_required {
        link.set_creds_without_reconnect(
            cred.node_id.trim().to_string(),
            cred.token.trim().to_string(),
            target,
            cred.published_targets.clone(),
        )
        .await;
    } else {
        link.set_creds(
            cred.node_id.trim().to_string(),
            cred.token.trim().to_string(),
            target,
            cred.published_targets.clone(),
        )
        .await;
    }
    if let Err(error) = persist_config_with_runtime_sync(
        &st,
        LegacyRuntimeSync {
            credentials: true,
            relay: replaces_relay,
        },
    )
    .await
    {
        if replaces_relay && let Err(rollback_error) = link.set_relay(previous_relay).await {
            tracing::error!(error = %rollback_error, "凭证配置持久化失败后无法回滚 relay 设置");
        }
        link.replace_creds(previous_creds).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存接入凭证失败: {error}"),
        ));
    }
    st.events
        .push("info", "credential", "已更新接入凭证，正在用新凭证重连");
    tracing::info!("凭证已更新，将以新凭证重连");
    let relay = link.relay_settings().await;
    let restart_required = link.relay_restart_required().await;
    let c = link.creds.read().await;
    Ok(Json(CredentialView {
        configured: true,
        node_id: c.node_id.clone(),
        token: c.token.clone(),
        token_hidden: false,
        published_targets: c.published_targets.clone(),
        relay,
        restart_required,
    }))
}

/// GET /api/export —— 默认下载脱敏配置。`?include_credentials=true` 仅在用户主动确认后使用。
#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default)]
    include_credentials: bool,
}

/// Backup/import payload: preserve the historical AConfig top-level shape and add an optional
/// relay field so older backups remain accepted without changing their representation.
#[derive(Serialize, Deserialize)]
struct TransferPayload {
    #[serde(flatten)]
    access: config::AConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay: Option<config::RelaySettings>,
}

async fn build_export_config(
    st: &AppState,
) -> Result<(config::AConfig, config::RelaySettings), String> {
    let runtime_relay = st
        .peers
        .legacy_default_relay_settings()
        .await
        .unwrap_or_default();
    let mut cfg = config::load_config(&st.config_path, None)
        .map_err(|error| format!("读取配置失败: {error}"))?
        .config;
    let access = merge_legacy_runtime_access(
        build_config(st).await?,
        cfg.access.as_ref(),
        &runtime_relay,
        LegacyRuntimeSync::NONE,
    );
    cfg.access = Some(access);
    cfg.normalize_access_peers()?;
    cfg.validate()?;
    Ok((
        cfg.access.expect("export config always has access"),
        cfg.relay,
    ))
}

async fn export_config(State(st): State<AppState>, Query(query): Query<ExportQuery>) -> Response {
    let (access, mut relay) = match build_export_config(&st).await {
        Ok(config) => config,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("导出配置失败: {error}"),
            )
                .into_response();
        }
    };
    let access = if query.include_credentials {
        access
    } else {
        access.redacted_for_export()
    };
    if !query.include_credentials {
        for entry in &mut relay.relays {
            entry.auth_token.clear();
        }
    };
    let payload = TransferPayload {
        access,
        relay: Some(relay),
    };
    match serde_json::to_string_pretty(&payload) {
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

/// Normalize a v0.9 backup into the persistent peer model before it touches any listener.
/// New backups must carry complete peer ownership; the only compatibility exception is the
/// historical single-credential shape, which becomes one named default peer here.
fn normalize_imported_access(
    mut incoming: config::AConfig,
    root_relay: Option<&config::RelaySettings>,
) -> Result<config::AConfig, String> {
    if incoming.peers.is_empty() {
        let relay = if incoming.relay != config::RelaySettings::default() {
            incoming.relay.clone()
        } else {
            root_relay.cloned().unwrap_or_default()
        };
        let peer = config::PeerConfig {
            id: config::new_peer_id(),
            name: "默认对端".into(),
            node_id: std::mem::take(&mut incoming.node_id),
            token: std::mem::take(&mut incoming.token),
            published_targets: std::mem::take(&mut incoming.published_targets),
            relay,
        };
        peer.validate()?;
        for mapping in &mut incoming.mappings {
            mapping.peer_id = peer.id.clone();
        }
        for mapping in &mut incoming.domain_mappings {
            mapping.peer_id = peer.id.clone();
        }
        if incoming.reverse_enabled && incoming.reverse_peer_id.trim().is_empty() {
            incoming.reverse_peer_id = peer.id.clone();
        }
        incoming.relay = config::RelaySettings::default();
        incoming.peers.push(peer);
    }
    incoming.validate()?;
    for peer in &incoming.peers {
        if !peer.node_id.trim().is_empty() {
            parse_target(&peer.node_id)?;
        }
    }
    Ok(incoming)
}

async fn persist_imported_peer_state(
    st: &AppState,
    root_relay: Option<&config::RelaySettings>,
) -> Result<(), String> {
    let _save = st.config_save.lock().await;
    let mut cfg = config::load_config(&st.config_path, None)
        .map_err(|error| format!("读取配置失败: {error}"))?
        .config;
    cfg.access = Some(build_config(st).await?);
    if let Some(root_relay) = root_relay {
        cfg.relay = root_relay.clone();
    }
    cfg.normalize_access_peers()?;
    cfg.validate()?;
    config::save(&st.config_path, &cfg).map_err(|error| format!("写入配置失败: {error}"))
}

/// Undo port and domain handles staged before an import commits. This is also used when a
/// same-address peer change has already stopped its old listener but the replacement cannot
/// bind: no staged handle or replacement peer configuration may escape that failure.
#[allow(clippy::too_many_arguments)]
async fn rollback_import_before_commit(
    st: &AppState,
    previous_peers: Vec<config::PeerConfig>,
    mut previous_mappings: HashMap<String, MappingHandle>,
    mut staged_mappings: HashMap<String, MappingHandle>,
    uncommitted_started_mappings: HashMap<String, MappingHandle>,
    started_locals: &HashSet<String>,
    replaced_mappings: Vec<(String, config::Mapping)>,
    rebuilt_mappings: Vec<(String, config::Mapping)>,
    started_domain_handles: HashMap<String, Arc<DomainMappingHandle>>,
    existing_domain_hosts: &HashMap<String, bool>,
) {
    if let Err(error) = st.peers.replace_peer_configs(previous_peers).await {
        tracing::error!(error = %error, "导入提交前回滚时无法恢复对端配置");
    }

    let mut mappings_to_stop = uncommitted_started_mappings
        .into_values()
        .collect::<Vec<_>>();
    for local in started_locals {
        if let Some(handle) = staged_mappings.remove(local) {
            mappings_to_stop.push(handle);
        }
    }
    for (local, _) in &rebuilt_mappings {
        if let Some(handle) = staged_mappings.remove(local) {
            mappings_to_stop.push(handle);
        }
    }
    for (local, previous_mapping) in replaced_mappings {
        if let Some(handle) = staged_mappings.get(&local) {
            *handle.mapping.write().await = previous_mapping;
        } else {
            tracing::error!(local, "导入提交前回滚时找不到已复用的映射");
        }
    }
    staged_mappings.extend(previous_mappings.drain());
    st.inner.lock().await.mappings = staged_mappings;

    for handle in mappings_to_stop {
        stop_mapping(st, handle).await;
    }
    for (local, previous_mapping) in rebuilt_mappings {
        match start_mapping_owned(st, previous_mapping).await {
            Ok(handle) => {
                st.inner.lock().await.mappings.insert(local, handle);
            }
            Err((_, error)) => {
                tracing::error!(error = %error, "导入提交前回滚时无法恢复对端变更前的映射");
            }
        }
    }
    for (domain, handle) in started_domain_handles {
        let remove_hosts = !existing_domain_hosts.get(&domain).copied().unwrap_or(false);
        if let Err(error) = stop_domain_mapping(st, handle, remove_hosts).await {
            tracing::error!(error = %error, domain, "导入提交前回滚时无法清理域名映射");
        }
    }
}

/// POST /api/import —— 事务式导入配置：应用映射 + 更新凭证 + 存盘。
/// `?mode=overwrite`（默认）整体替换映射；`?mode=merge` 只叠加，不删除现有其他映射。
/// 只接受 AConfig 结构；web_bind/TLS 等监听相关设置不热切换（需重启生效），
/// 这里只应用凭证与映射，避免把 Web 服务在运行中改瘫。
async fn import_config(
    State(st): State<AppState>,
    Query(query): Query<ImportQuery>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _mapping_operation = lock_mapping_operation(&st).await;
    let reverse_config_supplied = payload.as_object().is_some_and(|object| {
        [
            "reverse_enabled",
            "reverse_peer_id",
            "reverse_allow_networks",
            "reverse_allow_ports",
        ]
        .iter()
        .any(|field| object.contains_key(*field))
    });
    let payload = serde_json::from_value::<TransferPayload>(payload).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("导入配置格式错误: {error}"),
        )
    })?;
    let TransferPayload { access, relay } = payload;
    let legacy_payload = access.peers.is_empty();
    let legacy_credentials_omitted =
        access.node_id.trim().is_empty() && access.token.trim().is_empty();
    let legacy_relay_omitted = access.relay == config::RelaySettings::default() && relay.is_none();
    let mut incoming = normalize_imported_access(access, relay.as_ref())
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let merge = query.mode == ImportMode::Merge;
    if legacy_payload {
        // An old backup has no stable owner id. It is only compatible with the sole migrated
        // default peer, and omitted legacy credential/relay fields mean "leave it unchanged".
        let current = st
            .peers
            .legacy_default_peer_config()
            .await
            .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
        let generated_id = incoming.peers[0].id.clone();
        let effective_id = {
            let peer = incoming
                .peers
                .first_mut()
                .expect("legacy normalization adds one peer");
            peer.id = current.id.clone();
            if legacy_credentials_omitted {
                peer.node_id = current.node_id;
                peer.token = current.token;
                peer.published_targets = current.published_targets;
            }
            if legacy_relay_omitted {
                peer.relay = current.relay;
            }
            peer.id.clone()
        };
        for mapping in &mut incoming.mappings {
            if mapping.peer_id == generated_id {
                mapping.peer_id = effective_id.clone();
            }
        }
        for mapping in &mut incoming.domain_mappings {
            if mapping.peer_id == generated_id {
                mapping.peer_id = effective_id.clone();
            }
        }
        if incoming.reverse_peer_id == generated_id {
            incoming.reverse_peer_id = effective_id;
        }
    }
    if let Some(relay) = relay.as_ref() {
        relay
            .validate()
            .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
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
        if let Some(reason) = literal_loopback_acknowledgement_error(m) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("映射 {} 需要确认 loopback 风险: {reason}", m.local),
            ));
        }
        if !locals.insert(&m.local) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("本地监听地址 {} 重复", m.local),
            ));
        }
    }
    let mut domains = HashSet::new();
    for mapping in &incoming.domain_mappings {
        if let Err(reason) = mapping.validate() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("域名映射 {} 非法: {reason}", mapping.domain),
            ));
        }
        if !domains.insert(&mapping.domain) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("域名映射 {} 重复", mapping.domain),
            ));
        }
    }

    // 3) 在不触碰现有映射的前提下预启动所有端口和域名监听。相同 local 的端口监听
    // 保持原 socket，仅在所有新增监听成功后更新其目标，避免重绑同一端口的竞争窗口。
    let _domain_operation = lock_domain_operation(&st).await;
    let (existing_domains, existing_domain_hosts) = {
        let domains = st.domains.lock().await;
        (
            domains.mappings.keys().cloned().collect::<HashSet<_>>(),
            domains
                .mappings
                .iter()
                .map(|(domain, handle)| (domain.clone(), domain_handle_owns_hosts_marker(handle)))
                .collect::<HashMap<_, _>>(),
        )
    };
    let merged_domain_total = if merge {
        existing_domains.len()
            + incoming
                .domain_mappings
                .iter()
                .filter(|mapping| !existing_domains.contains(&mapping.domain))
                .count()
    } else {
        incoming.domain_mappings.len()
    };
    let domain_limit = config::domain_mapping_limit(st.max_mappings);
    if merged_domain_total > domain_limit {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("域名映射数 {merged_domain_total} 超过上限 {domain_limit}"),
        ));
    }
    let g = st.inner.lock().await;
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

    // Validate and install the complete peer collection before allocating any imported
    // listener. Mapping ownership is resolved against this staged collection, so a malformed
    // peer id/name/reference fails before it can alter the active listener set.
    let mut replacement_peers = if merge {
        st.peers
            .peer_configs()
            .await
            .into_iter()
            .map(|peer| (peer.id.clone(), peer))
            .collect::<HashMap<_, _>>()
    } else {
        HashMap::new()
    };
    for peer in &incoming.peers {
        replacement_peers.insert(peer.id.clone(), peer.clone());
    }
    drop(g);
    let previous_peers = st
        .peers
        .replace_peer_configs(replacement_peers.into_values().collect())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mut g = st.inner.lock().await;
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
                    stop_mapping(&st, handle).await;
                }
                if let Err(rollback_error) =
                    st.peers.replace_peer_configs(previous_peers.clone()).await
                {
                    tracing::error!(error = %rollback_error, "导入映射预启动失败后无法回滚对端配置");
                }
                return Err(error);
            }
        }
    }

    // Start domain handles before changing either runtime collection. Replacements use a new
    // handle so the old one remains available until the configuration write commits.
    let mut started_domain_handles = HashMap::new();
    for mapping in &incoming.domain_mappings {
        match start_domain_mapping_owned(&st, mapping.clone()).await {
            Ok(handle) => {
                started_domain_handles.insert(mapping.domain.clone(), handle);
            }
            Err(error) => {
                drop(g);
                for (_, handle) in started_handles {
                    stop_mapping(&st, handle).await;
                }
                for (domain, handle) in started_domain_handles {
                    let remove_hosts =
                        !existing_domain_hosts.get(&domain).copied().unwrap_or(false);
                    if let Err(cleanup_error) = stop_domain_mapping(&st, handle, remove_hosts).await
                    {
                        tracing::error!(error = %cleanup_error, domain, "域名映射导入预启动回滚不完整");
                    }
                }
                if let Err(rollback_error) =
                    st.peers.replace_peer_configs(previous_peers.clone()).await
                {
                    tracing::error!(error = %rollback_error, "导入域名映射预启动失败后无法回滚对端配置");
                }
                return Err(error);
            }
        }
    }

    // 全部新监听都已经成功，才一次性替换运行期集合。同地址条目复用监听任务，
    // 所以更新目标时不会因端口仍被旧监听占用而失败。
    let mut previous = std::mem::take(&mut g.mappings);
    let mut next = HashMap::with_capacity(merged_total);
    let started_locals = started_handles.keys().cloned().collect::<HashSet<_>>();
    let mut replaced_mappings = Vec::new();
    let mut rebuilt_mappings = Vec::new();
    let mut reused = 0usize;
    for mapping in &incoming.mappings {
        if let Some(handle) = previous.remove(&mapping.local) {
            let current = handle.mapping.read().await.clone();
            if handle.peer_id.is_some()
                && mapping.enabled
                && current.enabled
                && current.peer_id != mapping.peer_id
            {
                match rebuild_mapping_for_peer(&st, handle, mapping.clone()).await {
                    Ok(rebuilt) => {
                        rebuilt_mappings.push((mapping.local.clone(), current));
                        next.insert(mapping.local.clone(), rebuilt);
                    }
                    Err(error) => {
                        // `rebuild_mapping_for_peer` has already released `handle`, so retain
                        // its previous configuration explicitly and rebuild it during rollback.
                        rebuilt_mappings.push((mapping.local.clone(), current));
                        drop(g);
                        rollback_import_before_commit(
                            &st,
                            previous_peers.clone(),
                            previous,
                            next,
                            started_handles,
                            &started_locals,
                            replaced_mappings,
                            rebuilt_mappings,
                            started_domain_handles,
                            &existing_domain_hosts,
                        )
                        .await;
                        return Err(error);
                    }
                }
            } else {
                let mut current = handle.mapping.write().await;
                replaced_mappings.push((mapping.local.clone(), current.clone()));
                *current = mapping.clone();
                drop(current);
                next.insert(mapping.local.clone(), handle);
                reused += 1;
            }
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

    let mut previous_domain_mappings = {
        let mut domains = st.domains.lock().await;
        let previous = std::mem::take(&mut domains.mappings);
        let mut next = HashMap::with_capacity(merged_domain_total);
        for mapping in &incoming.domain_mappings {
            let handle = started_domain_handles
                .remove(&mapping.domain)
                .expect("预启动的域名监听必须存在");
            next.insert(mapping.domain.clone(), handle);
        }
        if merge {
            for (domain, handle) in &previous {
                if !next.contains_key(domain) {
                    next.insert(domain.clone(), handle.clone());
                }
            }
        }
        domains.mappings = next;
        previous
    };
    let previous_domain_hosts = previous_domain_mappings
        .iter()
        .map(|(domain, handle)| (domain.clone(), domain_handle_owns_hosts_marker(handle)))
        .collect::<HashMap<_, _>>();
    let imported_domain_names = incoming
        .domain_mappings
        .iter()
        .map(|mapping| mapping.domain.clone())
        .collect::<HashSet<_>>();
    let imported_domain_enabled = incoming
        .domain_mappings
        .iter()
        .map(|mapping| (mapping.domain.clone(), mapping.enabled))
        .collect::<HashMap<_, _>>();

    // 4) Persist the staged peer collection, mappings, and reverse owner as one configuration. The old
    // listeners remain available until this succeeds, allowing a failed disk write to restore
    // both listener ownership and the previous peer relay/credential state.
    let incoming_reverse = if reverse_config_supplied {
        ReverseConfig {
            enabled: incoming.reverse_enabled,
            peer_id: incoming.reverse_peer_id.clone(),
            allow_networks: incoming.reverse_allow_networks.clone(),
            allow_ports: incoming.reverse_allow_ports.clone(),
        }
    } else {
        st.reverse.read().await.clone()
    };
    let previous_reverse = std::mem::replace(&mut *st.reverse.write().await, incoming_reverse);
    let save = persist_imported_peer_state(&st, relay.as_ref()).await;
    if let Err(error) = save {
        *st.reverse.write().await = previous_reverse;
        if let Err(rollback_error) = st.peers.replace_peer_configs(previous_peers.clone()).await {
            tracing::error!(error = %rollback_error, "导入配置保存失败后无法回滚对端配置");
        }

        let started_to_stop = {
            let mut g = st.inner.lock().await;
            let mut current = std::mem::take(&mut g.mappings);
            let mut started_to_stop = Vec::new();
            for local in started_locals
                .iter()
                .chain(rebuilt_mappings.iter().map(|(local, _)| local))
            {
                if let Some(handle) = current.remove(local) {
                    started_to_stop.push(handle);
                }
            }
            for (local, previous_mapping) in replaced_mappings {
                if let Some(handle) = current.get(&local) {
                    *handle.mapping.write().await = previous_mapping;
                }
            }
            current.extend(previous);
            g.mappings = current;
            started_to_stop
        };
        for handle in started_to_stop {
            stop_mapping(&st, handle).await;
        }
        for (local, previous_mapping) in rebuilt_mappings {
            match start_mapping_owned(&st, previous_mapping).await {
                Ok(handle) => {
                    st.inner.lock().await.mappings.insert(local, handle);
                }
                Err((_, rollback_error)) => {
                    tracing::error!(error = %rollback_error, "导入配置保存失败后无法恢复对端变更前的映射");
                }
            }
        }
        let domains_to_stop = {
            let mut domains = st.domains.lock().await;
            let current = std::mem::take(&mut domains.mappings);
            domains.mappings = std::mem::take(&mut previous_domain_mappings);
            current
                .into_iter()
                .filter(|(domain, _)| imported_domain_names.contains(domain))
                .map(|(domain, handle)| {
                    let remove_hosts =
                        !previous_domain_hosts.get(&domain).copied().unwrap_or(false);
                    (domain, handle, remove_hosts)
                })
                .collect::<Vec<_>>()
        };
        for (domain, handle, remove_hosts) in domains_to_stop {
            if let Err(cleanup_error) = stop_domain_mapping(&st, handle, remove_hosts).await {
                tracing::error!(error = %cleanup_error, domain, "域名映射导入保存失败后的回滚不完整");
            }
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("导入配置保存失败: {error}"),
        ));
    }

    // 覆盖模式下被导入删除的映射到此才停止；合并模式下 previous 已被清空。
    for (_, handle) in previous {
        stop_mapping(&st, handle).await;
    }
    for (domain, handle) in previous_domain_mappings {
        let remove_hosts = match imported_domain_enabled.get(&domain) {
            Some(enabled) => !enabled,
            None if !merge => true,
            None => continue,
        };
        if let Err(error) = stop_domain_mapping(&st, handle, remove_hosts).await {
            tracing::error!(error = %error, domain, "导入提交后清理旧域名映射失败");
            if remove_hosts && imported_domain_names.contains(&domain) {
                record_domain_cleanup_failure(&st, &domain, error).await;
            }
        }
    }
    let started = incoming.mappings.len();
    tracing::info!(started, reused, kept, merge, "已导入配置");
    st.events.push(
        "info",
        "mapping",
        format!(
            "已{}配置：{started} 条映射{}",
            if merge { "合并" } else { "导入" },
            "，对端配置已更新"
        ),
    );
    Ok(Json(serde_json::json!({
        "started": started,
        "failed": [],
        "reused": reused,
        "kept": kept,
        "merged": merge,
        "credential_updated": !incoming.peers.is_empty(),
        "restart_required": false,
    })))
}

/// 停止一条映射并等待监听 socket 释放，供导入失败回滚和删除的映射复用。
async fn stop_mapping(st: &AppState, handle: MappingHandle) {
    let peer_id = handle.peer_id.clone();
    handle.cancel.cancel();
    handle.task.abort();
    let _ = handle.task.await;
    if let Some(peer_id) = peer_id {
        st.peers.release_link(&peer_id).await;
    }
}

/// 运行接入侧：`cfg` 已由外壳完成凭证/CLI 覆写，这里校验后绑定 iroh endpoint、
/// 恢复映射、起看门狗与反向驱动，并提供 Web 管理页，直到 `cancel` 触发再优雅关停。
pub async fn run(
    cfg: config::AConfig,
    config_path: PathBuf,
    cancel: CancellationToken,
    local_expose_id: Option<PublicKey>,
) -> Result<()> {
    cfg.validate().map_err(anyhow::Error::msg)?;
    let peers = PeerManager::new(cfg.peers.clone(), cancel.clone(), local_expose_id)
        .map_err(anyhow::Error::msg)?;

    let tls_enabled = !cfg.web_tls_cert.is_empty();

    config::save_access(&config_path, &cfg)?;
    tracing::info!("配置文件: {}", config_path.display());

    let metrics = Metrics::new();
    let events = EventLog::new(200);
    let state = AppState {
        peers: peers.clone(),
        web_bind: cfg.web_bind.clone(),
        web_token: cfg.web_token.clone(),
        web_tls_cert: cfg.web_tls_cert.clone(),
        web_tls_key: cfg.web_tls_key.clone(),
        web_allowed_hosts: cfg.web_allowed_hosts.clone(),
        max_mappings: cfg.max_mappings,
        max_conns_per_mapping: cfg.max_conns_per_mapping,
        domains: Arc::new(Mutex::new(DomainInner {
            mappings: HashMap::new(),
            listener: None,
        })),
        domain_lifecycle: Arc::new(Mutex::new(())),
        mapping_lifecycle: Arc::new(Mutex::new(())),
        // Unsupported platforms retain ordinary port mappings. Domain operations themselves
        // return a typed unsupported-platform error before this inert path can be used.
        hosts: HostsStore::system()
            .unwrap_or_else(|_| HostsStore::at("/unsupported/powermap-hosts")),
        domain_listener: system_domain_listener(),
        mapping_listener: system_mapping_listener(),
        domain_admin_check: Arc::new(current_process_admin),
        domain_preflight: domain_preflight(peers),
        config_path: config_path.clone(),
        metrics: metrics.clone(),
        events: events.clone(),
        inner: Arc::new(Mutex::new(Inner {
            mappings: HashMap::new(),
        })),
        config_save: Arc::new(Mutex::new(())),
        relay_update: Arc::new(Mutex::new(())),
        updater: update::UpdateCoordinator::new(cancel.clone()),
        reverse: Arc::new(RwLock::new(ReverseConfig {
            enabled: cfg.reverse_enabled,
            peer_id: cfg.reverse_peer_id.clone(),
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

    // 反向映射驱动：开启后在到 B 的同一条连接上发一条 register 流（让 B 起内网反向监听），
    // 随后循环 accept_bi 接收 B 发起的反向流，每条按 A 端 deny-all 策略校验后回拨 A 一侧目标。
    // 连接断开则重来；关闭反向时不注册（即便有残留流，策略也会一律拒绝）。
    let reverse_state = state.clone();
    let reverse_metrics = metrics.clone();
    tokio::spawn(async move {
        // A 端回拨自己一侧目标的拨号超时，与正向 server 侧保持一致量级。
        const REVERSE_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let reverse = reverse_state.reverse.read().await.clone();
            if !reverse.enabled {
                continue;
            }
            let (reverse_peer_id, reverse_link) = match reverse_state
                .peers
                .acquire_reverse_link(&reverse.peer_id)
                .await
            {
                Ok(link) => link,
                Err(_) => continue,
            };
            if !reverse_link.configured().await {
                reverse_state.peers.release_link(&reverse_peer_id).await;
                continue;
            }
            let conn = match reverse_link.get().await {
                Ok(c) => c,
                Err(_) => {
                    reverse_state.peers.release_link(&reverse_peer_id).await;
                    continue;
                }
            };
            // 在既有连接上开一条 register 流：B 据此认证连接并启动该客户的反向监听。
            let (mut send, mut recv) = match conn.open_bi().await {
                Ok(s) => s,
                Err(_) => {
                    reverse_state.peers.release_link(&reverse_peer_id).await;
                    continue;
                }
            };
            let req = proto::OpenRequest {
                token: reverse_link.token().await,
                host: String::new(),
                port: 0,
                kind: proto::TunnelKind::Tcp,
                register: true,
                preflight: false,
                allow_loopback_target: false,
            };
            if proto::write_open(&mut send, &req).await.is_err() {
                reverse_state.peers.release_link(&reverse_peer_id).await;
                continue;
            }
            match proto::read_status(&mut recv).await {
                Ok(proto::OpenStatus::Ok) => {
                    reverse_state.events.push(
                        "info",
                        "reverse",
                        "反向映射已注册，开始接受 server 发起的反向连接",
                    );
                    tracing::info!("反向注册成功，开始接受 B 的反向流");
                }
                Ok(proto::OpenStatus::Error(msg)) | Ok(proto::OpenStatus::LoopRisk(msg)) => {
                    // B 未为该客户配置反向监听等：稍等再试，避免忙循环。
                    tracing::debug!(reason = %msg, "B 拒绝反向注册");
                    reverse_state.peers.release_link(&reverse_peer_id).await;
                    tokio::time::sleep(Duration::from_secs(20)).await;
                    continue;
                }
                Err(_) => {
                    reverse_state.peers.release_link(&reverse_peer_id).await;
                    continue;
                }
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
            reverse_state.peers.release_link(&reverse_peer_id).await;
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
