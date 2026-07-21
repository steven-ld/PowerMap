//! 优雅关闭信号：同时监听 Ctrl+C（SIGINT）和 SIGTERM，
//! 这样 `docker stop` 发的 SIGTERM 也能触发正常退出。

#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
pub async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
