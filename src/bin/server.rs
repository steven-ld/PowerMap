//! 穿透端 B —— 部署在内网设备上。
//!
//! 首次运行生成配置（含持久化身份与令牌）并写入默认配置目录；之后每次启动
//! 直接复用同一份配置，node id 与 token 保持稳定，A 端无需重新拿凭证。
//! 对外用 iroh 中继暴露一个 ALPN 服务；收到 A 的连接后，按握手头里的
//! "目标主机:端口"认证 token、按该客户白名单校验、在内网拨号并双向透传（支持半关闭）。
//!
//! 多租户：配置里可写多个 `[[clients]]`，各自独立 token 与白名单，可单独吊销/轮换；
//! 顶层单 token 会被归一化为 id="default" 的客户，兼容旧配置。
//! B 不暴露任何入站端口，指标周期性打到日志，审计事件写入可选审计文件。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, SecretKey};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

use powermap::metrics::Metrics;
use powermap::{config, proto, signal, tunnel};

#[derive(Parser)]
#[command(
    name = "powermap-server",
    version,
    about = "iroh P2P 穿透端：部署在内网设备，生成凭证供 A 端接入（支持多租户）"
)]
struct Args {
    /// 配置文件路径（默认 <配置目录>/powermap/powermap-server.toml）
    #[arg(long)]
    config: Option<PathBuf>,
    /// 指定单租户 token（hex）；优先于配置文件，且会回写
    #[arg(long)]
    token: Option<String>,
    /// 中继上线等待超时（秒）
    #[arg(long, default_value_t = 20)]
    online_timeout: u64,
}

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

fn load_or_create_key(path: &std::path::Path) -> Result<SecretKey> {
    if path.exists() {
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
        loop {
            match connection.accept_bi().await {
                Ok((mut send, mut recv)) => {
                    // 先读握手头，据此分流：register（建立反向监听）/ 正向隧道。
                    let req = match proto::read_open(&mut recv).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(error = %e, "读取隧道握手头失败，丢弃该流");
                            continue;
                        }
                    };

                    // register 流：认证 token，为该客户在内网启动反向监听（仅首个 register 生效）。
                    if req.register {
                        self.handle_register(&connection, &peer, &mut send, &req, &reverse_cancel)
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
        if cancel.is_cancelled() {
            let _ = proto::write_status(send, proto::STATUS_ERR, "already registered").await;
            return;
        }
        let _ = proto::write_status(send, proto::STATUS_OK, "").await;
        tracing::info!(client = %client.id, %peer, count = listens.len(), "已接受反向注册，启动内网反向监听");
        for listen in listens {
            let conn = connection.clone();
            let metrics = self.metrics.clone();
            let child = cancel.child_token();
            let client_id = client.id.clone();
            tokio::spawn(async move {
                if let Err(e) = run_reverse_listener(conn, listen, metrics, child).await {
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
    listen: config::ReverseListen,
    metrics: Arc<Metrics>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&listen.listen)
        .await
        .with_context(|| format!("绑定反向监听 {} 失败", listen.listen))?;
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iroh=warn,powermap_server=info,audit=info".into()),
        )
        .init();

    let args = Args::parse();
    let config_path = args
        .config
        .unwrap_or_else(|| config::default_path("powermap-server.toml"));
    let mut cfg: config::BConfig = config::load_or_default(&config_path)?;
    if let Some(t) = args.token.clone() {
        cfg.token = t;
    }
    cfg.validate().map_err(anyhow::Error::msg)?;

    let identity_path = resolve_identity(&config_path, &cfg.identity);
    let secret_key = load_or_create_key(&identity_path)?;

    // 首次运行（既无顶层 token 也无 clients）则生成一个默认 token 并回写配置
    let freshly_set_up = cfg.token.is_empty() && cfg.clients.is_empty();
    if freshly_set_up {
        cfg.token = proto::to_hex(&SecretKey::generate().to_bytes());
    }
    config::save(&config_path, &cfg)?;

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

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![proto::ALPN.to_vec()])
        .transport_config(tunnel::transport_config())
        .bind()
        .await
        .context("绑定 iroh endpoint 失败")?;

    let node_id = endpoint.id().to_string();
    tracing::info!("配置文件: {}", config_path.display());
    tracing::info!("身份文件: {}", identity_path.display());
    tracing::info!("node id: {node_id}");
    tracing::info!("等待中继上线（online）…");
    if tokio::time::timeout(Duration::from_secs(args.online_timeout), endpoint.online())
        .await
        .is_err()
    {
        tracing::warn!(
            "{} 秒内未完成中继握手，继续运行（A 端可能仍能通过后续发现连入）",
            args.online_timeout
        );
    }

    // 凭证文件：单租户模式下始终刷新写到配置目录（携带 default token），方便复制给 A 端。
    // 多租户模式（无顶层 token）下不写单一凭证，避免误导。
    if !default_token.is_empty() {
        let cred = tunnel::Credential {
            node_id: node_id.clone(),
            token: default_token.clone(),
            published_targets: cfg.published_targets.clone(),
        };
        let cred_path = config_path.with_file_name("powermap-server.credential.json");
        std::fs::write(&cred_path, serde_json::to_string_pretty(&cred)?)?;
        tracing::info!("凭证已写入 {}（把它交给 A 端）", cred_path.display());
        if freshly_set_up {
            println!("--- 首次配置完成，把下面这份凭证交给 A 端 ---");
            println!("{}", serde_json::to_string_pretty(&cred)?);
            println!("-------------------------------------------");
        }
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
    tracing::info!("powermap-server 就绪，Ctrl+C 或 SIGTERM 退出");

    signal::shutdown_signal().await;
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
