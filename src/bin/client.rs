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
//! - 可选 TLS（web_tls_cert/web_tls_key），远程管理时保护 Bearer token；
//! - 映射条数与单映射并发连接数有上限，防止无限增长耗尽资源。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use clap::Parser;
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use powermap::metrics::Metrics;
use powermap::{config, proto, signal, tunnel};

#[derive(Parser)]
#[command(
    name = "powermap-client",
    version,
    about = "iroh P2P 用户端：家里电脑，Web 管理端口映射"
)]
struct Args {
    /// 配置文件路径（默认 <配置目录>/powermap/powermap-client.toml）
    #[arg(long)]
    config: Option<PathBuf>,
    /// 凭证文件路径或 JSON 字符串；仅首次接入需要，会写入配置
    #[arg(long)]
    credential: Option<String>,
    /// Web 管理页监听地址（覆盖配置）
    #[arg(long)]
    web: Option<String>,
    /// Web 管理页访问令牌（覆盖配置）；留空则不鉴权
    #[arg(long)]
    web_token: Option<String>,
    /// Web TLS 证书路径（PEM，覆盖配置）
    #[arg(long)]
    web_tls_cert: Option<String>,
    /// Web TLS 私钥路径（PEM，覆盖配置）
    #[arg(long)]
    web_tls_key: Option<String>,
}

/// 运行期可变的接入凭证：连接目标（node_id → PublicKey）与访问令牌。
/// 网页配置凭证后原地更新，隧道随即用新凭证连接，无需重启进程。
/// `target` 为 None 表示尚未配置凭证（client 可无凭证启动）。
#[derive(Clone, Default)]
struct Creds {
    node_id: String,
    token: String,
    target: Option<PublicKey>,
}

/// 到 B 的共享连接池：所有映射的隧道都复用同一条 iroh 连接（QUIC 多流），
/// 连接断开时懒重连。连接目标来自可变的 `Creds`，网页改凭证即时生效。
#[derive(Clone)]
struct Link {
    endpoint: Endpoint,
    creds: Arc<RwLock<Creds>>,
    conn: Arc<Mutex<Option<Connection>>>,
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
        tracing::info!("已（重）连到 B");
        Ok(c)
    }

    async fn invalidate(&self) {
        *self.conn.lock().await = None;
    }

    /// 切换连接目标：更新凭证并断开当前连接，下次 get() 用新凭证重连。
    async fn set_creds(&self, node_id: String, token: String, target: PublicKey) {
        {
            let mut c = self.creds.write().await;
            c.node_id = node_id;
            c.token = token;
            c.target = Some(target);
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

    /// 当前到 B 的穿透路径：direct（P2P 打洞直连）/ relay（经中继转发）/ unknown（暂不可知）。
    /// 读 iroh 的 remote_info，看当前活跃的传输地址是 IP（直连）还是 Relay（中继）。
    /// 未连接或无凭证时返回 None。
    async fn transport_path(&self) -> Option<&'static str> {
        let target = self.creds.read().await.target?;
        if !self.is_alive().await {
            return None;
        }
        let info = self.endpoint.remote_info(target).await?;
        let mut has_direct = false;
        let mut has_relay = false;
        for a in info.addrs() {
            if !matches!(a.usage(), iroh::endpoint::TransportAddrUsage::Active) {
                continue;
            }
            match a.addr() {
                iroh::TransportAddr::Ip(_) => has_direct = true,
                iroh::TransportAddr::Relay(_) => has_relay = true,
                _ => {}
            }
        }
        // 有活跃直连即视为 P2P（iroh 会尽量升级到直连）；否则若有活跃中继则为 relay。
        if has_direct {
            Some("direct")
        } else if has_relay {
            Some("relay")
        } else {
            Some("unknown")
        }
    }
}

/// 单条映射的流量统计（按块增量累加，实时可见）。
struct Stats {
    tx: AtomicU64, // 本地 -> 远端（上行）
    rx: AtomicU64, // 远端 -> 本地（下行）
    diagnostics: RwLock<MappingDiagnostics>,
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
    last_tunnel_failure: Option<TunnelFailure>,
    last_tunnel_success_at: Option<u64>,
    last_outcome: TunnelOutcome,
}

impl Stats {
    fn new() -> Arc<Stats> {
        Arc::new(Stats {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            diagnostics: RwLock::new(MappingDiagnostics {
                listener_active: true,
                ..Default::default()
            }),
        })
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
        let state = if !diagnostics.listener_active {
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

#[derive(Clone)]
struct AppState {
    link: Link,
    web_bind: String,
    web_token: String,
    web_tls_cert: String,
    web_tls_key: String,
    max_mappings: usize,
    max_conns_per_mapping: usize,
    config_path: PathBuf,
    metrics: Arc<Metrics>,
    inner: Arc<Mutex<Inner>>,
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

/// 一条隧道：开流、握手、本地与远端双向透传（优雅半关闭 + 流量计数 + 全局指标）。
async fn handle_tunnel(
    link: Link,
    req: proto::OpenRequest,
    local: TcpStream,
    stats: Arc<Stats>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (mut send, mut recv) = open_with_retry(&link, &req).await?;
    metrics.tunnel_open();
    stats.record_success().await;
    let (mut l_read, mut l_write) = tokio::io::split(local);
    let up = async {
        tunnel::copy_count(&mut l_read, &mut send, &[&stats.tx, &metrics.bytes_tx]).await?;
        send.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let down = async {
        tunnel::copy_count(&mut recv, &mut l_write, &[&stats.rx, &metrics.bytes_rx]).await?;
        l_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::try_join!(up, down);
    metrics.tunnel_close();
    result.map(|_| ())
}

// ---- HTTP handlers ----

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
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
}

async fn status(State(st): State<AppState>) -> Json<Status> {
    let n = st.inner.lock().await.mappings.len();
    let path = st.link.transport_path().await;
    let creds = st.link.creds.read().await;
    let m = &st.metrics;
    Json(Status {
        connected: st.link.is_alive().await,
        configured: creds.target.is_some(),
        node_id: creds.node_id.clone(),
        mappings: n,
        path,
        version: env!("CARGO_PKG_VERSION"),
        active_tunnels: m.tunnels_active.load(Ordering::Relaxed),
        tunnels_opened: m.tunnels_opened.load(Ordering::Relaxed),
        tunnels_failed: m.tunnels_failed.load(Ordering::Relaxed),
        reconnects: m.reconnects.load(Ordering::Relaxed),
        over_limit: m.over_limit.load(Ordering::Relaxed),
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

    async fn test_state(web_token: &str) -> AppState {
        let endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        AppState {
            link: Link {
                endpoint,
                creds: Arc::new(RwLock::new(Creds::default())),
                conn: Arc::new(Mutex::new(None)),
            },
            web_bind: "127.0.0.1:0".into(),
            web_token: web_token.into(),
            web_tls_cert: String::new(),
            web_tls_key: String::new(),
            max_mappings: 8,
            max_conns_per_mapping: 8,
            config_path: std::env::temp_dir().join(format!("powermap-client-test-{suffix}.toml")),
            metrics: Metrics::new(),
            inner: Arc::new(Mutex::new(Inner {
                mappings: HashMap::new(),
            })),
        }
    }

    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
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
    async fn mapping_mutations_enforce_auth_and_accept_a_valid_bearer_token() {
        let state = test_state("admin-secret").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let unauthorized = app
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
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer admin-secret")
                    .body(Body::from(format!(
                        r#"{{"local":"{local}","host":"127.0.0.1","port":80}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);

        let removed = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/mappings/{local}"))
                    .header(header::AUTHORIZATION, "Bearer admin-secret")
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
    async fn query_string_tokens_do_not_authorize_management_requests() {
        let state = test_state("admin-secret").await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mappings?token=admin-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"local":"{local}","host":"127.0.0.1","port":80}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

#[derive(Serialize)]
struct StatItem {
    local: String,
    host: String,
    port: u16,
    tx_bytes: u64,
    rx_bytes: u64,
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
            tx_bytes: stats.tx.load(Ordering::Relaxed),
            rx_bytes: stats.rx.load(Ordering::Relaxed),
            diagnostics: stats.diagnostic_snapshot().await,
        });
    }
    Json(result)
}

#[derive(Deserialize)]
struct CreateBody {
    local: String,
    host: String,
    port: u16,
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
    };
    if let Err(reason) = mapping.validate() {
        return Err((StatusCode::BAD_REQUEST, reason));
    }

    let mut checks = BTreeMap::new();
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
        let request = proto::OpenRequest {
            token: st.link.token().await,
            host: mapping.host.clone(),
            port: mapping.port,
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
    Ok(Json(mapping))
}

/// 启动一条映射的本地监听；返回运行期把手（含取消令牌）。
async fn start_mapping_owned(
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
                Ok((tcp, _)) => {
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
                        // 每条隧道建立时实时读取当前令牌，凭证轮换后新连接立即生效。
                        let mapping = mapping.read().await;
                        let req = proto::OpenRequest {
                            token: link.token().await,
                            host: mapping.host.clone(),
                            port: mapping.port,
                        };
                        tokio::select! {
                            _ = child.cancelled() => {}
                            r = handle_tunnel(link.clone(), req, tcp, stats_for_tunnel, metrics.clone()) => {
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

async fn remove(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.mappings.remove(&id) {
        Some(h) => {
            // 先取消（drain 在途连接：停止 accept + 取消所有子隧道），再 abort 监听任务。
            h.cancel.cancel();
            h.task.abort();
            drop(g);
            save_config(&st).await;
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}

/// Web API 鉴权：配置了 web_token 时，只接受 Authorization: Bearer；
/// /api/health 与 /metrics 免鉴权（供健康检查与抓取；/metrics 仅暴露聚合计数，不含机密）。
async fn require_auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if st.web_token.is_empty() || path == "/api/health" || path == "/metrics" {
        return next.run(req).await;
    }
    let from_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()));
    match from_header {
        Some(t) if powermap::tunnel::token_ok(&st.web_token, &t) => next.run(req).await,
        _ => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/metrics", get(metrics_handler))
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/stats", get(stats))
        .route("/api/mappings/preflight", post(preflight))
        .route("/api/mappings", get(list).post(create))
        .route("/api/mappings/{id}", delete(remove))
        .route("/api/credential", get(get_credential).post(set_credential))
        .route("/api/export", get(export_config))
        .route("/api/import", post(import_config))
        .with_state(state.clone())
        .layer(from_fn_with_state(state, require_auth))
}

/// 从当前运行期状态构建一份完整配置（凭证 + 设置 + 映射）。save_config 与导出接口共用。
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
    let (node_id, token) = {
        let c = st.link.creds.read().await;
        (c.node_id.clone(), c.token.clone())
    };
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
    }
}

async fn save_config(st: &AppState) {
    let cfg = build_config(st).await;
    if let Err(e) = config::save(&st.config_path, &cfg) {
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

/// 非回环绑定且未设 web_token 时，拒绝在接口里回显 token（避免明文泄露给任意来访者）。
/// 回环（本机）默认放行，方便本地使用。
fn token_exposable(st: &AppState) -> bool {
    let is_loopback = st
        .web_bind
        .split(':')
        .next()
        .map(|h| h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]")
        .unwrap_or(false);
    is_loopback || !st.web_token.is_empty()
}

// ---- 凭证 / 导入导出 ----

#[derive(Serialize)]
struct CredentialView {
    configured: bool,
    node_id: String,
    /// 当前接入令牌；非回环且未设 web_token 时置空并由 token_hidden 标记原因。
    token: String,
    token_hidden: bool,
}

/// GET /api/credential —— 供网页查看/复制当前凭证。
async fn get_credential(State(st): State<AppState>) -> Json<CredentialView> {
    let c = st.link.creds.read().await;
    let expose = token_exposable(&st);
    Json(CredentialView {
        configured: c.target.is_some(),
        node_id: c.node_id.clone(),
        token: if expose {
            c.token.clone()
        } else {
            String::new()
        },
        token_hidden: !expose && !c.token.is_empty(),
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
        )
        .await;
    save_config(&st).await;
    tracing::info!("凭证已更新，将以新凭证重连");
    let expose = token_exposable(&st);
    let c = st.link.creds.read().await;
    Ok(Json(CredentialView {
        configured: true,
        node_id: c.node_id.clone(),
        token: if expose {
            c.token.clone()
        } else {
            String::new()
        },
        token_hidden: !expose && !c.token.is_empty(),
    }))
}

/// GET /api/export —— 下载完整配置（凭证 + 设置 + 映射）JSON。
async fn export_config(State(st): State<AppState>) -> Response {
    if !token_exposable(&st) {
        return (
            StatusCode::FORBIDDEN,
            "非回环绑定且未设 web_token，拒绝导出（配置含明文 token）。请先设置 web_token。",
        )
            .into_response();
    }
    let cfg = build_config(&st).await;
    match serde_json::to_string_pretty(&cfg) {
        Ok(body) => (
            [
                ("content-type", "application/json"),
                (
                    "content-disposition",
                    "attachment; filename=\"powermap-client.config.json\"",
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

/// POST /api/import —— 事务式导入整份配置：覆盖映射 + 更新凭证 + 存盘。
/// 只接受 AConfig 结构；web_bind/web_token/TLS 等监听相关设置不热切换（需重启生效），
/// 这里只应用凭证与映射，避免把 Web 服务在运行中改瘫。
async fn import_config(
    State(st): State<AppState>,
    Json(incoming): Json<config::AConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    if st.max_mappings > 0 && incoming.mappings.len() > st.max_mappings {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "导入映射数 {} 超过上限 {}",
                incoming.mappings.len(),
                st.max_mappings
            ),
        ));
    }

    // 3) 在不触碰现有映射的前提下预启动所有新增监听。相同 local 的监听保持
    // 原 socket，仅在所有新增监听成功后更新其目标，避免重绑同一端口的竞争窗口。
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
                    stop_mapping(handle).await;
                }
                return Err(error);
            }
        }
    }

    // 全部新监听都已经成功，才一次性替换运行期集合。同地址条目复用监听任务，
    // 所以更新目标时不会因端口仍被旧监听占用而失败。
    let mut previous = std::mem::take(&mut g.mappings);
    let mut next = HashMap::with_capacity(incoming.mappings.len());
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
    g.mappings = next;
    drop(g);

    // 被导入配置删除的映射在新集合提交后才停止，不会影响失败回滚路径。
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
            )
            .await;
    }
    save_config(&st).await;
    let started = incoming.mappings.len();
    tracing::info!(started, reused, "已导入配置");
    Ok(Json(serde_json::json!({
        "started": started,
        "failed": [],
        "reused": reused,
        "credential_updated": new_target.is_some(),
    })))
}

/// 停止一条映射并等待监听 socket 释放，供导入失败回滚和删除的映射复用。
async fn stop_mapping(handle: MappingHandle) {
    handle.cancel.cancel();
    handle.task.abort();
    let _ = handle.task.await;
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iroh=warn,powermap_client=info".into()),
        )
        .init();

    let args = Args::parse();
    let config_path = args
        .config
        .unwrap_or_else(|| config::default_path("powermap-client.toml"));
    let mut cfg: config::AConfig = config::load_or_default(&config_path)?;

    // 首次接入：把凭证写入配置
    if let Some(cred_src) = &args.credential {
        let s = std::fs::read_to_string(cred_src).unwrap_or_else(|_| cred_src.clone());
        let cred: tunnel::Credential =
            serde_json::from_str(&s).context("解析凭证失败（应为 {node_id, token} JSON）")?;
        cfg.node_id = cred.node_id;
        cfg.token = cred.token;
    }
    if let Some(w) = args.web {
        cfg.web_bind = w;
    }
    if let Some(t) = args.web_token {
        cfg.web_token = t;
    }
    if let Some(c) = args.web_tls_cert {
        cfg.web_tls_cert = c;
    }
    if let Some(k) = args.web_tls_key {
        cfg.web_tls_key = k;
    }
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

    // 非回环管理已由配置校验强制要求 web_token；TLS 仍可由可信 HTTPS 反代提供。
    let is_loopback = cfg
        .web_bind
        .parse::<SocketAddr>()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    if !is_loopback && !tls_enabled {
        tracing::warn!(
            "Web 监听 {} 非回环且未启用 TLS，Bearer token 将以明文传输！建议配置 web_tls_cert/web_tls_key 或置于 HTTPS 反代之后。",
            cfg.web_bind
        );
    }

    config::save(&config_path, &cfg)?;
    tracing::info!("配置文件: {}", config_path.display());

    let metrics = Metrics::new();
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
        })),
        conn: Arc::new(Mutex::new(None)),
    };
    let state = AppState {
        link: link.clone(),
        web_bind: cfg.web_bind.clone(),
        web_token: cfg.web_token.clone(),
        web_tls_cert: cfg.web_tls_cert.clone(),
        web_tls_key: cfg.web_tls_key.clone(),
        max_mappings: cfg.max_mappings,
        max_conns_per_mapping: cfg.max_conns_per_mapping,
        config_path: config_path.clone(),
        metrics: metrics.clone(),
        inner: Arc::new(Mutex::new(Inner {
            mappings: HashMap::new(),
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

    // 看门狗：保持到 B 的热连接，断线（close_reason 置位）时按指数退避主动重连，
    // 避免 B 宕机时疯狂重连打爆
    let watchdog_link = link.clone();
    let watchdog_metrics = metrics.clone();
    tokio::spawn(async move {
        let mut failures: u32 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // 尚未配置凭证时不尝试连接，静候网页粘贴凭证。
            if !watchdog_link.configured().await {
                failures = 0;
                continue;
            }
            if watchdog_link.is_alive().await {
                failures = 0;
                continue;
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
                    Metrics::inc(&watchdog_metrics.reconnects);
                    tracing::info!(?delay, "看门狗：已重连");
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    tracing::debug!(failures, error = %e, "看门狗重连暂未成功");
                }
            }
        }
    });

    let app = app(state.clone());

    let bind_addr: SocketAddr = cfg
        .web_bind
        .parse()
        .with_context(|| format!("web_bind 不是合法地址: {}", cfg.web_bind))?;
    let auth_hint = if cfg.web_token.is_empty() {
        "（未鉴权）"
    } else {
        "（已开启 Bearer 鉴权）"
    };
    let scheme = if tls_enabled { "https" } else { "http" };
    tracing::info!("Web 管理页: {}://{} {}", scheme, cfg.web_bind, auth_hint);

    // 优雅关闭：收到 SIGINT/SIGTERM 后 drain 所有映射的在途隧道，再停止 HTTP。
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        signal::shutdown_signal().await;
        tracing::info!("收到关闭信号，drain 在途隧道…");
        // 取消所有映射的监听与子隧道
        {
            let g = shutdown_state.inner.lock().await;
            for h in g.mappings.values() {
                h.cancel.cancel();
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
    tracing::info!("已关闭");
    Ok(())
}
