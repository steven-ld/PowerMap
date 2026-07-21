//! 极简 Prometheus 文本指标：用原子计数器实现，不引入第三方 metrics 依赖。
//!
//! A 端通过 `/metrics` 暴露；B 端不开入站端口，改为周期性打到 tracing / 审计日志，
//! 以保持"B 不暴露任何入站端口"这一部署特性。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// 进程级运行指标。所有字段都是单调递增计数器，except `tunnels_active` 是瞬时量（gauge）。
#[derive(Default)]
pub struct Metrics {
    /// 成功建立的隧道累计数
    pub tunnels_opened: AtomicU64,
    /// 当前活跃隧道数（gauge）
    pub tunnels_active: AtomicU64,
    /// 建立失败的隧道累计数（握手后任意环节失败）
    pub tunnels_failed: AtomicU64,
    /// 令牌被拒（未知 / 吊销）累计数
    pub handshake_denied: AtomicU64,
    /// 目标被白名单策略拒绝累计数
    pub target_denied: AtomicU64,
    /// 因并发上限被拒累计数
    pub over_limit: AtomicU64,
    /// 内网拨号失败累计数
    pub dial_failed: AtomicU64,
    /// 内网拨号超时累计数
    pub dial_timeout: AtomicU64,
    /// 看门狗重连累计次数（A 端）
    pub reconnects: AtomicU64,
    /// 发送给对端字节累计
    pub bytes_tx: AtomicU64,
    /// 从对端接收字节累计
    pub bytes_rx: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn tunnel_open(&self) {
        self.tunnels_opened.fetch_add(1, Ordering::Relaxed);
        self.tunnels_active.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn tunnel_close(&self) {
        // 饱和递减，避免下溢
        let mut cur = self.tunnels_active.load(Ordering::Relaxed);
        while cur > 0 {
            match self.tunnels_active.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }

    /// 渲染成 Prometheus 文本曝露格式。
    pub fn render(&self) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut s = String::with_capacity(1024);
        let mut line = |name: &str, typ: &str, help: &str, val: u64| {
            s.push_str(&format!("# HELP {name} {help}\n"));
            s.push_str(&format!("# TYPE {name} {typ}\n"));
            s.push_str(&format!("{name} {val}\n"));
        };
        line(
            "powermap_tunnels_opened_total",
            "counter",
            "Total tunnels successfully opened",
            g(&self.tunnels_opened),
        );
        line(
            "powermap_tunnels_active",
            "gauge",
            "Currently active tunnels",
            g(&self.tunnels_active),
        );
        line(
            "powermap_tunnels_failed_total",
            "counter",
            "Total tunnels that failed to establish",
            g(&self.tunnels_failed),
        );
        line(
            "powermap_handshake_denied_total",
            "counter",
            "Total handshakes denied (unknown or revoked token)",
            g(&self.handshake_denied),
        );
        line(
            "powermap_target_denied_total",
            "counter",
            "Total targets denied by allowlist policy",
            g(&self.target_denied),
        );
        line(
            "powermap_over_limit_total",
            "counter",
            "Total tunnels rejected due to concurrency limit",
            g(&self.over_limit),
        );
        line(
            "powermap_dial_failed_total",
            "counter",
            "Total intranet dial failures",
            g(&self.dial_failed),
        );
        line(
            "powermap_dial_timeout_total",
            "counter",
            "Total intranet dial timeouts",
            g(&self.dial_timeout),
        );
        line(
            "powermap_reconnects_total",
            "counter",
            "Total watchdog reconnects",
            g(&self.reconnects),
        );
        line(
            "powermap_bytes_tx_total",
            "counter",
            "Total bytes sent to peer",
            g(&self.bytes_tx),
        );
        line(
            "powermap_bytes_rx_total",
            "counter",
            "Total bytes received from peer",
            g(&self.bytes_rx),
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_never_underflows() {
        let m = Metrics::default();
        m.tunnel_close(); // 从 0 关闭，不应下溢
        assert_eq!(m.tunnels_active.load(Ordering::Relaxed), 0);
        m.tunnel_open();
        m.tunnel_open();
        m.tunnel_close();
        assert_eq!(m.tunnels_active.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn render_contains_prometheus_format() {
        let m = Metrics::default();
        m.tunnels_opened.fetch_add(3, Ordering::Relaxed);
        let out = m.render();
        assert!(out.contains("# TYPE powermap_tunnels_opened_total counter"));
        assert!(out.contains("powermap_tunnels_opened_total 3"));
        assert!(out.contains("powermap_tunnels_active 0"));
    }
}
