use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;
use iroh::SecretKey;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use powermap::{access, config, expose, proto, signal, update};

#[derive(Parser)]
#[command(name = "powermap", version, about = "P2P private-network access")]
struct Args {
    /// Unified configuration path (default: <config-dir>/powermap.toml)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Relay online wait timeout for the expose role, in seconds.
    #[arg(long, default_value_t = 20)]
    online_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let result = run().await;
    if let Err(error) = result {
        return update::rollback_failed_start(error);
    }
    Ok(())
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iroh=warn,powermap=info,audit=info".into()),
        )
        .init();

    let args = Args::parse();
    let path = args
        .config
        .unwrap_or_else(|| config::default_path("powermap.toml"));
    let mut loaded = config::load_config(&path, None)?;

    if let Some(expose) = &mut loaded.config.expose
        && expose.token.is_empty()
        && expose.clients.is_empty()
    {
        expose.token = proto::to_hex(&SecretKey::generate().to_bytes());
    }
    loaded.config.validate().map_err(anyhow::Error::msg)?;
    config::save(&loaded.path, &loaded.config)?;

    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    tokio::spawn(async move {
        signal::shutdown_signal().await;
        signal_cancel.cancel();
    });

    let mut tasks = JoinSet::new();
    if let Some(expose_cfg) = loaded.config.expose {
        tasks.spawn(expose::run(
            expose_cfg,
            loaded.path.clone(),
            args.online_timeout,
            cancel.clone(),
        ));
    }
    if let Some(access_cfg) = loaded.config.access {
        tasks.spawn(access::run(access_cfg, loaded.path, cancel.clone()));
    }

    // A freshly exec'd update retains its old binary until the new process has survived its
    // startup gate. Most configuration and bind failures surface immediately in a worker task.
    if let Ok(Some(result)) = tokio::time::timeout(Duration::from_secs(2), tasks.join_next()).await
    {
        let result = result?;
        cancel.cancel();
        while tasks.join_next().await.is_some() {}
        return result;
    }
    update::confirm_startup()?;

    let result = tasks
        .join_next()
        .await
        .expect("at least one configured role")?;
    cancel.cancel();
    while tasks.join_next().await.is_some() {}
    result
}
