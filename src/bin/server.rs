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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, SecretKey};
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
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
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
                        if let Err(e) = tunnel::serve_stream(send, recv, &ctx).await {
                            tracing::warn!(error = %e, "隧道流结束");
                        }
                    });
                }
                // 连接关闭：本连接上的流由各自任务处理完后自然退出
                Err(_) => return Ok(()),
            }
        }
    }
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
