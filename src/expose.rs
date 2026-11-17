//! 暴露侧（expose，原 server 角色）运行逻辑。
//!
//! 部署在内网设备上：对外用 iroh 中继暴露一个 ALPN 服务；收到接入方（access）的
//! 连接后，按握手头里的"目标主机:端口"认证 token、按该客户白名单校验、在内网拨号
//! 并双向透传（支持半关闭）。多租户下每个 `[[clients]]` 各自独立 token 与白名单。
//!
//! 本模块只承载运行期逻辑；进程外壳（日志初始化、CLI 解析、配置加载）留在调用方
//! （统一 `powermap` 入口）。关停由外部传入的 `CancellationToken`
//! 驱动，便于两角色共存时统一协调退出。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, SecretKey};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;
use crate::{config, proto, relay_runtime, tunnel};

/// 对端建立流后必须在此时限内发出握手头，否则丢弃该流。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn resolve_identity(config_path: &Path, identity: &str) -> PathBuf {
    let p = PathBuf::from(identity);
    if p.is_absolute() {
        p
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(p)
    }
}

/// 把文件权限收紧到仅属主可读写（Unix）。Windows 上由用户目录 ACL 决定，无需处理。
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(path = %path.display(), %error, "收紧文件权限失败");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn load_or_create_key(path: &std::path::Path) -> Result<SecretKey> {
    if path.exists() {
        // 旧版本以默认 umask 写入（常见 0644），读到就顺手收紧。
        restrict_to_owner(path);
        let hex = std::fs::read_to_string(path)
            .with_context(|| format!("读取身份文件失败: {}", path.display()))?;
        let bytes = proto::from_hex(hex.trim()).context("身份文件不是合法的 hex")?;
        let mut arr = [0u8; 32];
        anyhow::ensure!(bytes.len() == 32, "身份文件必须是 32 字节");
        arr.copy_from_slice(&bytes);
        Ok(SecretKey::from_bytes(&arr))
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let sk = SecretKey::generate();
        // 先以 0600 创建，再写入内容，避免密钥在 0644 窗口内被同机其他用户读取。
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("创建身份文件失败: {}", path.display()))?;
            file.write_all(proto::to_hex(&sk.to_bytes()).as_bytes())?;
        }
        #[cfg(not(unix))]
        std::fs::write(path, proto::to_hex(&sk.to_bytes()))?;
        Ok(sk)
    }
}

/// ALPN 协议处理器：每个对端连接上循环 accept_bi，每条流 = 一条隧道。
/// 用连接级信号量限制单连接并发隧道数，防止单个对端开海量流打爆 B。
#[derive(Clone)]
struct TunnelHandler {
    registry: Arc<tunnel::ClientRegistry>,
    metrics: Arc<Metrics>,
    audit: tunnel::Audit,
    dial_timeout: Duration,
    max_streams_per_conn: usize,
    /// 客户 id → 该客户的反向监听列表。A 端注册连接后，B 为对应客户在内网起这些监听，
    /// 每个内网连接经隧道交给 A 拨其一侧目标。空表示该客户无反向监听。
    reverse: Arc<std::collections::HashMap<String, Vec<config::ReverseListen>>>,
}

impl std::fmt::Debug for TunnelHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for TunnelHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id().to_string();
        // 每连接一把信号量，限制该连接上的并发隧道数（0 = 不限）。
        let sem = (self.max_streams_per_conn > 0)
            .then(|| Arc::new(Semaphore::new(self.max_streams_per_conn)));
        // 该连接上已启动的反向监听（首个 register 流触发；连接结束时随 CancellationToken 关闭）。
        let reverse_cancel = tokio_util::sync::CancellationToken::new();
        // 每条连接只允许一个 register 流；用独立标志而不是 cancel 状态判断，
        // 后者在连接存活期间永远为 false，重复 register 会被当作首次处理。
        let registered = Arc::new(AtomicBool::new(false));
        loop {
            match connection.accept_bi().await {
                Ok((mut send, mut recv)) => {
                    // 先读握手头，据此分流：register（建立反向监听）/ 正向隧道。
                    // 对端可以只开流不发头，必须有超时，否则一条连接就能阻塞 accept 循环。
                    let req =
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, proto::read_open(&mut recv))
                            .await
                        {
                            Ok(Ok(r)) => r,
                            Ok(Err(e)) => {
                                tracing::warn!(error = %e, "读取隧道握手头失败，丢弃该流");
                                continue;
                            }
                            Err(_) => {
                                tracing::warn!(%peer, "读取隧道握手头超时，丢弃该流");
                                continue;
                            }
                        };

                    // register 流：认证 token，为该客户在内网启动反向监听（仅首个 register 生效）。
                    if req.register {
                        self.handle_register(
                            &connection,
                            &peer,
                            &mut send,
                            &req,
                            &reverse_cancel,
                            &registered,
                        )
                        .await;
                        continue;
                    }

                    // 超过单连接并发上限：直接丢弃这条流（不 spawn），并计数。
                    let permit = match &sem {
                        Some(s) => match s.clone().try_acquire_owned() {
                            Ok(p) => Some(p),
                            Err(_) => {
                                Metrics::inc(&self.metrics.over_limit);
                                drop((send, recv));
                                continue;
                            }
                        },
                        None => None,
                    };
                    let ctx = Arc::new(tunnel::ServeCtx {
                        registry: self.registry.clone(),
                        metrics: self.metrics.clone(),
                        audit: self.audit.clone(),
                        dial_timeout: self.dial_timeout,
                        peer: peer.clone(),
                    });
                    tokio::spawn(async move {
                        let _permit = permit; // 持有至隧道结束
                        if let Err(e) = tunnel::serve_forward(send, recv, req, &ctx).await {
                            tracing::warn!(error = %e, "隧道流结束");
                        }
                    });
                }
                // 连接关闭：本连接上的流由各自任务处理完后自然退出；反向监听随之关闭。
                Err(_) => {
                    reverse_cancel.cancel();
                    return Ok(());
                }
            }
        }
    }
}

impl TunnelHandler {
    /// 处理一条 register 流：认证 token，若该客户配置了反向监听且尚未在本连接启动，
    /// 则为其在内网绑定这些监听。每个内网连接经隧道交给 A 端拨其一侧目标。
    /// register 流保持打开作为存活信号——回一个状态码后即返回，流的关闭由连接生命周期决定。
    async fn handle_register(
        &self,
        connection: &Connection,
        peer: &str,
        send: &mut iroh::endpoint::SendStream,
        req: &proto::OpenRequest,
        cancel: &tokio_util::sync::CancellationToken,
        registered: &AtomicBool,
    ) {
        let client = match self.registry.authenticate(&req.token) {
            Some(c) => c,
            None => {
                Metrics::inc(&self.metrics.handshake_denied);
                let _ = proto::write_status(send, proto::STATUS_ERR, "bad token").await;
                tracing::warn!(%peer, "register 流 token 无效，拒绝");
                return;
            }
        };
        let listens = self.reverse.get(&client.id).cloned().unwrap_or_default();
        if listens.is_empty() {
            let _ = proto::write_status(send, proto::STATUS_ERR, "no reverse listeners").await;
            return;
        }
        // 已在本连接启动过反向监听则忽略重复 register。
        if registered.swap(true, Ordering::SeqCst) {
            let _ = proto::write_status(send, proto::STATUS_ERR, "already registered").await;
            return;
        }
        // 先绑定全部内网监听，全部成功才回 OK；否则 A 端会以为注册成功，
        // 而实际监听从未建立。绑定失败时允许重试（回滚标志）。
        let mut bound = Vec::with_capacity(listens.len());
        for listen in listens {
            match tokio::net::TcpListener::bind(&listen.listen).await {
                Ok(listener) => bound.push((listener, listen)),
                Err(error) => {
                    registered.store(false, Ordering::SeqCst);
                    let _ = proto::write_status(
                        send,
                        proto::STATUS_ERR,
                        &format!("bind {} failed: {error}", listen.listen),
                    )
                    .await;
                    tracing::warn!(client = %client.id, %peer, listen = %listen.listen, %error, "反向监听绑定失败");
                    return;
                }
            }
        }
        let _ = proto::write_status(send, proto::STATUS_OK, "").await;
        tracing::info!(client = %client.id, %peer, count = bound.len(), "已接受反向注册，启动内网反向监听");
        for (listener, listen) in bound {
            let conn = connection.clone();
            let metrics = self.metrics.clone();
            let child = cancel.child_token();
            let client_id = client.id.clone();
            tokio::spawn(async move {
                if let Err(e) = run_reverse_listener(conn, listener, listen, metrics, child).await {
                    tracing::warn!(client = %client_id, error = %e, "反向监听退出");
                }
            });
        }
    }
}

/// 在内网绑定一条反向监听：每个到来的内网连接在既有 A→B 连接上开一条流，
/// 写目标（A 一侧要拨的 host:port），随后与 A 双向透传。A 端按其 deny-all 策略校验并回拨。
async fn run_reverse_listener(
    connection: Connection,
    listener: tokio::net::TcpListener,
    listen: config::ReverseListen,
    metrics: Arc<Metrics>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    tracing::info!(listen = %listen.listen, target = %format!("{}:{}", listen.target_host, listen.target_port), name = %listen.name, "反向监听已就绪");
    loop {
        let (mut tcp, _peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => r?,
        };
        let conn = connection.clone();
        let metrics = metrics.clone();
        let host = listen.target_host.clone();
        let port = listen.target_port;
        let child = cancel.child_token();
        tokio::spawn(async move {
            // 连接可能已随 A 断开而失效；开流失败则关闭这条内网连接。
            let (mut send, mut recv) = match conn.open_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "反向开流失败（A 可能已断开）");
                    return;
                }
            };
            let req = proto::OpenRequest {
                token: String::new(), // 反向流复用已认证连接，无需再带 token
                host,
                port,
                kind: proto::TunnelKind::Tcp,
                register: false,
            };
            if proto::write_open(&mut send, &req).await.is_err() {
                return;
            }
            match proto::read_status(&mut recv).await {
                Ok(Ok(())) => {}
                Ok(Err(msg)) => {
                    tracing::debug!(reason = %msg, "A 端拒绝反向目标");
                    return;
                }
                Err(_) => return,
            }
            metrics.tunnel_open();
            let (mut t_read, mut t_write) = tcp.split();
            let up = async {
                tunnel::copy_count(&mut t_read, &mut send, &[&metrics.bytes_tx]).await?;
                send.shutdown().await.ok();
                Ok::<_, std::io::Error>(())
            };
            let down = async {
                tunnel::copy_count(&mut recv, &mut t_write, &[&metrics.bytes_rx]).await?;
                t_write.shutdown().await.ok();
                Ok::<_, std::io::Error>(())
            };
            let _ = tokio::select! {
                _ = child.cancelled() => Ok(()),
                r = async { tokio::try_join!(up, down).map(|_| ()) } => r,
            };
            metrics.tunnel_close();
        });
    }
    Ok(())
}

/// 运行暴露侧：加载好的 `cfg` 经校验后绑定 iroh endpoint、启动 ALPN 服务，直到
/// `cancel` 触发。首次运行（既无顶层 token 也无 clients）会生成默认 token 并回写配置。
pub async fn run(
    cfg: config::BConfig,
    relay: config::RelaySettings,
    config_path: PathBuf,
    online_timeout: u64,
    cancel: CancellationToken,
) -> Result<()> {
    cfg.validate().map_err(anyhow::Error::msg)?;

    let identity_path = resolve_identity(&config_path, &cfg.identity);
    let secret_key = load_or_create_key(&identity_path)?;

    // 归一化多租户客户端列表（顶层单 token 折叠为 id="default"）
    let clients = cfg.effective_clients();
    let default_token = cfg.token.clone();
    if cfg.uses_legacy_single_token() {
        tracing::info!(
            "检测到兼容的顶层 token 单租户配置；它会继续作为 id=default 的客户生效。迁移到 [[clients]] 是可选的。"
        );
    }
    let registry = Arc::new(tunnel::ClientRegistry::from_configs(&clients));
    if registry.is_empty() {
        anyhow::bail!("没有任何可用客户端凭证（token 均为空或全部吊销）");
    }

    // 白名单告警（针对每个未受限客户）
    for c in &clients {
        if !c.revoked && c.allow_networks.is_empty() && c.allow_ports.is_empty() {
            tracing::warn!(
                client = %c.id,
                "客户 {} 未配置目标白名单，其 token 持有者可拨号内网任意 host:port",
                c.id
            );
        }
    }
    tracing::info!("已加载 {} 个客户端凭证", registry.len());

    // 客户 id → 反向监听列表。仅收录非吊销且确有反向监听的客户；A 端注册后按此启动内网监听。
    let reverse_map: HashMap<String, Vec<config::ReverseListen>> = clients
        .iter()
        .filter(|c| !c.revoked && !c.reverse.is_empty())
        .map(|c| (c.id.clone(), c.reverse.clone()))
        .collect();
    if !reverse_map.is_empty() {
        let total: usize = reverse_map.values().map(|v| v.len()).sum();
        tracing::info!(
            clients = reverse_map.len(),
            listeners = total,
            "已配置反向监听；将在对应 A 端注册连接后启动"
        );
    }
    let reverse = Arc::new(reverse_map);

    let metrics = Metrics::new();
    let audit = if cfg.audit_log.is_empty() {
        tunnel::Audit::disabled()
    } else {
        tracing::info!("审计日志: {}", cfg.audit_log);
        tunnel::Audit::to_file(&cfg.audit_log)
    };
    let dial_timeout = Duration::from_secs(cfg.dial_timeout_secs.max(1));
    let relay_mode = relay.relay_mode().map_err(anyhow::Error::msg)?;
    let primary_relay_urls = relay_mode.relay_map().urls::<Vec<_>>();
    let force_relay = relay.force_relay;

    let endpoint_builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![proto::ALPN.to_vec()])
        .relay_mode(relay_mode)
        .transport_config(tunnel::transport_config());
    let endpoint_builder = if force_relay {
        endpoint_builder.clear_ip_transports()
    } else {
        endpoint_builder
    };
    let endpoint = endpoint_builder
        .bind()
        .await
        .context("绑定 iroh endpoint 失败")?;
    if force_relay {
        tracing::warn!("已启用强制中继：此 expose Endpoint 不会尝试 P2P 直连");
    }

    if relay.uses_official_primary() {
        let fallback_endpoint = endpoint.clone();
        let fallback_cancel = cancel.clone();
        let fallback_grace = Duration::from_secs(online_timeout.max(1));
        tokio::spawn(async move {
            if relay_runtime::wait_for_primary_relay_failure(
                fallback_endpoint.clone(),
                fallback_grace,
                fallback_cancel,
            )
            .await
            {
                relay_runtime::install_iroh_fallback(&fallback_endpoint, &primary_relay_urls).await;
                tracing::warn!("官方中继不可用，已启用 iroh 默认中继后备");
            }
        });
    }

    let node_id = endpoint.id().to_string();
    tracing::info!("配置文件: {}", config_path.display());
    tracing::info!("身份文件: {}", identity_path.display());
    tracing::info!("node id: {node_id}");
    tracing::info!("等待中继上线（online）…");
    if tokio::time::timeout(Duration::from_secs(online_timeout), endpoint.online())
        .await
        .is_err()
    {
        tracing::warn!(
            "{} 秒内未完成中继握手，继续运行（A 端可能仍能通过后续发现连入）",
            online_timeout
        );
    }

    // 凭证文件：单租户模式下始终刷新写到配置目录（携带 default token），方便复制给 A 端。
    // 多租户模式（无顶层 token）下不写单一凭证，避免误导。
    if !default_token.is_empty() {
        let cred = tunnel::Credential {
            node_id: node_id.clone(),
            token: default_token.clone(),
            published_targets: cfg.published_targets.clone(),
            relay: None,
        };
        let cred_path = config_path.with_file_name("powermap.credential.json");
        std::fs::write(&cred_path, serde_json::to_string_pretty(&cred)?)?;
        // 凭证含可直接拨号的 token，不能留在默认 umask 的 0644 上。
        restrict_to_owner(&cred_path);
        tracing::info!("凭证已写入 {}（把它交给 A 端）", cred_path.display());
    } else {
        tracing::info!("多租户模式：请分别向各客户分发其 node_id + token");
    }

    // 周期性把指标打到日志（B 不开入站端口，故不暴露 /metrics）
    let mstat = metrics.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            use std::sync::atomic::Ordering::Relaxed;
            tracing::info!(
                target: "metrics",
                active = mstat.tunnels_active.load(Relaxed),
                opened = mstat.tunnels_opened.load(Relaxed),
                failed = mstat.tunnels_failed.load(Relaxed),
                denied_token = mstat.handshake_denied.load(Relaxed),
                denied_target = mstat.target_denied.load(Relaxed),
                over_limit = mstat.over_limit.load(Relaxed),
                dial_failed = mstat.dial_failed.load(Relaxed),
                dial_timeout = mstat.dial_timeout.load(Relaxed),
                "metrics"
            );
        }
    });

    let handler = TunnelHandler {
        registry,
        metrics,
        audit,
        dial_timeout,
        max_streams_per_conn: cfg.max_streams_per_conn,
        reverse,
    };
    let router = Router::builder(endpoint)
        .accept(proto::ALPN, handler)
        .spawn();
    tracing::info!("PowerMap expose 已就绪，Ctrl+C 或 SIGTERM 退出");

    cancel.cancelled().await;
    tracing::info!("正在关闭…");
    let _ = router.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn start_server(allow_ports: Vec<u16>) -> (Router, iroh::EndpointAddr, Arc<Metrics>) {
        let metrics = Metrics::new();
        let registry = Arc::new(tunnel::ClientRegistry::from_configs(&[
            config::ClientCred {
                id: "test-client".into(),
                token: "test-token".into(),
                allow_networks: vec!["127.0.0.0/8".into()],
                allow_ports,
                published_targets: vec![],
                reverse: vec![],
                max_streams: 0,
                revoked: false,
            },
        ]));
        let handler = TunnelHandler {
            registry,
            metrics: metrics.clone(),
            audit: tunnel::Audit::disabled(),
            dial_timeout: Duration::from_secs(2),
            max_streams_per_conn: 0,
            reverse: Arc::new(std::collections::HashMap::new()),
        };
        let endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
        let addr = endpoint.addr();
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, handler)
            .spawn();
        (router, addr, metrics)
    }

    async fn connect(addr: iroh::EndpointAddr) -> (Endpoint, Connection) {
        let endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
        let connection =
            tokio::time::timeout(Duration::from_secs(5), endpoint.connect(addr, proto::ALPN))
                .await
                .expect("iroh connection timed out")
                .expect("iroh connection failed");
        (endpoint, connection)
    }

    #[tokio::test]
    async fn iroh_tunnel_relays_bytes_to_an_allowed_local_target() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut request = [0; 9];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"PowerMap!");
            socket.write_all(b"relayed").await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let (router, server_addr, _) = start_server(vec![target_addr.port()]).await;
        let (client_endpoint, connection) = connect(server_addr).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        proto::write_open(
            &mut send,
            &proto::OpenRequest {
                token: "test-token".into(),
                host: "127.0.0.1".into(),
                port: target_addr.port(),
                kind: proto::TunnelKind::Tcp,
                register: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(proto::read_status(&mut recv).await.unwrap(), Ok(()));

        send.write_all(b"PowerMap!").await.unwrap();
        send.shutdown().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"relayed");

        echo.await.unwrap();
        connection.close(0u8.into(), b"test complete");
        client_endpoint.close().await;
        router.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn iroh_tunnel_rejects_a_target_port_outside_the_server_allowlist() {
        let (router, server_addr, metrics) = start_server(vec![443]).await;
        let (client_endpoint, connection) = connect(server_addr).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        proto::write_open(
            &mut send,
            &proto::OpenRequest {
                token: "test-token".into(),
                host: "127.0.0.1".into(),
                port: 6379,
                kind: proto::TunnelKind::Tcp,
                register: false,
            },
        )
        .await
        .unwrap();

        let status = proto::read_status(&mut recv).await.unwrap();
        assert!(
            matches!(status, Err(message) if message.contains("6379") && message.contains("允许列表"))
        );
        assert_eq!(metrics.target_denied.load(Ordering::Relaxed), 1);

        connection.close(0u8.into(), b"test complete");
        client_endpoint.close().await;
        router.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn iroh_udp_tunnel_relays_datagrams_to_an_allowed_target() {
        // 内网 UDP echo 目标：收到一个数据报后原样加前缀回发。
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, from) = target.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            target.send_to(b"pong", from).await.unwrap();
        });

        let (router, server_addr, _) = start_server(vec![target_addr.port()]).await;
        let (client_endpoint, connection) = connect(server_addr).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        proto::write_open(
            &mut send,
            &proto::OpenRequest {
                token: "test-token".into(),
                host: "127.0.0.1".into(),
                port: target_addr.port(),
                kind: proto::TunnelKind::Udp,
                register: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(proto::read_status(&mut recv).await.unwrap(), Ok(()));

        // 上行一个数据报，读回下行数据报（均带 2 字节长度前缀）。
        proto::write_datagram(&mut send, b"ping").await.unwrap();
        let mut buf = Vec::new();
        let n = proto::read_datagram(&mut recv, &mut buf).await.unwrap();
        assert_eq!(n, Some(4));
        assert_eq!(&buf[..], b"pong");

        echo.await.unwrap();
        connection.close(0u8.into(), b"test complete");
        client_endpoint.close().await;
        router.shutdown().await.unwrap();
    }
}
