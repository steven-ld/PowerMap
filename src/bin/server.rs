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
//!
//! 本 binary 只是薄壳：解析 CLI、加载配置、初始化日志，随后把运行逻辑交给
//! `powermap::expose::run`。真正的隧道处理与端到端测试都在 `src/expose.rs`。

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use powermap::{config, expose, signal};

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

    // 收到 SIGINT/SIGTERM 后触发 cancel，run 据此优雅关停。
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        signal::shutdown_signal().await;
        shutdown.cancel();
    });

    expose::run(cfg, config_path, args.online_timeout, cancel).await
}
