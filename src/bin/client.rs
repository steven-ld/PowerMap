//! 用户端 A —— 装在家里（或任意想访问内网服务的）电脑上。
//!
//! 首次用 `--credential` 接入一次后，凭证与映射规则都写入配置文件，之后直接
//! 启动即可，无需重复配置；映射规则重启自动恢复。
//!
//! Web 管理页（默认 http://127.0.0.1:8088）支持增删映射。每条映射在本地起一个
//! TCP 监听；每来一个连接，就复用同一条到 B 的 iroh 连接开一条 QUIC 流，握手
//! 带上"目标主机:端口"与令牌，B 在内网拨号后双向透传（支持半关闭）。
//!
//! 本 binary 只是薄壳：解析 CLI、加载配置、初始化日志、按 CLI 覆写凭证与 Web 选项，
//! 随后把运行逻辑交给 `powermap::access::run`。真正的映射与 Web 管理都在 `src/access.rs`。

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;

use powermap::{access, config, signal, tunnel};

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
        cfg.published_targets = cred.published_targets;
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

    // 收到 SIGINT/SIGTERM 后触发 cancel，run 据此 drain 在途隧道并优雅关停。
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        signal::shutdown_signal().await;
        shutdown.cancel();
    });

    access::run(cfg, config_path, cancel).await
}
