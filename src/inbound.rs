//! 入站连接登记表：expose 侧把「谁连到了本机」登记下来，管理页读取展示。
//!
//! 只在进程内使用，不落盘：连接断开即从表中移除，进程重启后从零开始。
//! 表里同时记录认证后的客户 id、连接路径、活跃隧道数，这样管理页既能回答
//! 「谁连了我」，也能看出它是不是当前正在用隧道、是否注册了反向监听。
//!
//! 多角色同进程时由 `bin/powermap.rs` 创建一份共享实例：expose 侧写入，
//! access 侧的管理 API 读取；只跑 access 时该表为空（`/api/inbound` 报未启用）。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::Mutex;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

/// 一条入站连接的管理页视图。
#[derive(Clone, Debug, Serialize)]
pub struct InboundView {
    /// 对端 iroh node id（公钥十六进制）。
    pub node_id: String,
    /// 认证后的客户 id（expose 配置里的 `[[clients]].id`）；该连接还没认证过时为 None。
    pub client_id: Option<String>,
    /// 远端地址：直连时是 `IP:端口`，经中继时是中继主机名。
    pub remote_addr: Option<String>,
    /// 连接路径：`direct` / `relay` / `unknown`。
    pub path: String,
    /// 选定路径的往返延迟（毫秒）。
    pub rtt_ms: Option<u64>,
    /// 连接建立时刻（unix 毫秒）。
    pub connected_at: u64,
    /// 最近一次观察到活动（开隧道 / 注册 / 认证）的时刻（unix 毫秒）。
    pub last_seen_at: u64,
    /// 该连接上当前活跃的隧道数。
    pub active_tunnels: usize,
    /// 该连接累计成功开始的隧道数。
    pub tunnels_opened: u64,
    /// 该连接累计被拒绝的请求数（令牌错误 / 超过并发上限）。
    pub tunnels_denied: u64,
    /// 该连接是否已注册反向监听。
    pub registered: bool,
}

#[derive(Debug)]
struct Entry {
    node_id: String,
    client_id: Option<String>,
    remote_addr: Option<String>,
    path: String,
    rtt_ms: Option<u64>,
    connected_at: u64,
    last_seen_at: u64,
    active_tunnels: usize,
    tunnels_opened: u64,
    tunnels_denied: u64,
    registered: bool,
}

/// 进程内共享的入站连接表。克隆开销是 `Arc` 克隆。
#[derive(Debug)]
pub struct InboundRegistry {
    entries: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
}

impl InboundRegistry {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    /// 登记一条新连接，返回用于后续更新与关闭的句柄。
    pub async fn open(
        self: &Arc<Self>,
        node_id: String,
        remote_addr: Option<String>,
        path: String,
        rtt_ms: Option<u64>,
    ) -> InboundHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = now_ms();
        self.entries.lock().await.insert(
            id,
            Entry {
                node_id,
                client_id: None,
                remote_addr,
                path,
                rtt_ms,
                connected_at: now,
                last_seen_at: now,
                active_tunnels: 0,
                tunnels_opened: 0,
                tunnels_denied: 0,
                registered: false,
            },
        );
        InboundHandle {
            registry: self.clone(),
            id,
        }
    }

    /// 当前所有入站连接，按建立时间倒序（最近的在前）。
    pub async fn snapshot(&self) -> Vec<InboundView> {
        let entries = self.entries.lock().await;
        let mut views = entries
            .values()
            .map(|entry| InboundView {
                node_id: entry.node_id.clone(),
                client_id: entry.client_id.clone(),
                remote_addr: entry.remote_addr.clone(),
                path: entry.path.clone(),
                rtt_ms: entry.rtt_ms,
                connected_at: entry.connected_at,
                last_seen_at: entry.last_seen_at,
                active_tunnels: entry.active_tunnels,
                tunnels_opened: entry.tunnels_opened,
                tunnels_denied: entry.tunnels_denied,
                registered: entry.registered,
            })
            .collect::<Vec<_>>();
        views.sort_by(|a, b| b.connected_at.cmp(&a.connected_at));
        views
    }

    /// 当前连接数，供状态卡直接显示。
    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }
}

/// 单条入站连接的写句柄。连接结束时调用 [`InboundHandle::close`]；句柄本身不实现
/// `Drop` 清理——清理是异步的，交由 accept 循环显式执行，避免静默丢表项。
#[derive(Clone, Debug)]
pub struct InboundHandle {
    registry: Arc<InboundRegistry>,
    id: u64,
}

impl InboundHandle {
    /// 认证成功：记录是哪个客户在连。同一连接上以最新一次认证为准。
    pub async fn authenticate(&self, client_id: &str) {
        self.update(|entry| {
            entry.client_id = Some(client_id.to_owned());
        })
        .await;
    }

    /// 一条正向隧道开始转发。
    pub async fn tunnel_started(&self) {
        self.update(|entry| {
            entry.active_tunnels += 1;
            entry.tunnels_opened += 1;
        })
        .await;
    }

    /// 一条正向隧道结束（含异常结束）。
    pub async fn tunnel_finished(&self) {
        self.update(|entry| {
            entry.active_tunnels = entry.active_tunnels.saturating_sub(1);
        })
        .await;
    }

    /// 请求被拒绝：令牌无效或超过并发上限。
    pub async fn denied(&self) {
        self.update(|entry| {
            entry.tunnels_denied += 1;
        })
        .await;
    }

    /// 该连接已注册反向监听。
    pub async fn registered(&self) {
        self.update(|entry| entry.registered = true).await;
    }

    /// 连接结束，从表中移除。
    pub async fn close(&self) {
        self.registry.entries.lock().await.remove(&self.id);
    }

    async fn update(&self, apply: impl FnOnce(&mut Entry)) {
        let mut entries = self.registry.entries.lock().await;
        if let Some(entry) = entries.get_mut(&self.id) {
            apply(entry);
            entry.last_seen_at = now_ms();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracks_clients_tunnels_and_removes_closed_connections() {
        let registry = InboundRegistry::new();
        let handle = registry
            .open(
                "peer-a".into(),
                Some("203.0.113.9:4433".into()),
                "direct".into(),
                Some(12),
            )
            .await;

        let views = registry.snapshot().await;
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].node_id, "peer-a");
        assert_eq!(views[0].path, "direct");
        assert!(views[0].client_id.is_none());
        assert_eq!(views[0].active_tunnels, 0);

        handle.authenticate("client-1").await;
        handle.tunnel_started().await;
        handle.tunnel_started().await;
        handle.tunnel_finished().await;
        handle.registered().await;
        handle.denied().await;

        let views = registry.snapshot().await;
        let view = &views[0];
        assert_eq!(view.client_id.as_deref(), Some("client-1"));
        assert_eq!(view.active_tunnels, 1);
        assert_eq!(view.tunnels_opened, 2);
        assert_eq!(view.tunnels_denied, 1);
        assert!(view.registered);

        handle.close().await;
        assert!(registry.snapshot().await.is_empty());
        assert_eq!(registry.len().await, 0);
    }

    #[tokio::test]
    async fn close_is_idempotent_for_stale_handles() {
        let registry = InboundRegistry::new();
        let first = registry
            .open("peer-a".into(), None, "unknown".into(), None)
            .await;
        let second = first.clone();
        first.close().await;
        second.close().await;
        assert!(registry.snapshot().await.is_empty());
    }
}
