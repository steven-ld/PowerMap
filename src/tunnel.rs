//! A/B 两端共享的隧道逻辑：凭证结构、多租户令牌校验、目标策略、审计、B 端单流转发。

use anyhow::{Result, bail};
use ipnet::IpNet;
use iroh::endpoint::{QuicTransportConfig, VarInt};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};

use crate::config;
use crate::metrics::Metrics;
use crate::proto;

/// QUIC 传输参数：
/// - 5s keepalive（保活）+ 15s 空闲超时，使对端失联后 ~15s 内被察觉（配合 A 端看门狗）；
/// - 调大并发双向流上限与流量窗口，避免忙碌 Web 服务撞上默认并发流天花板导致隐性排队。
pub fn transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(1024))
        .default_path_max_idle_timeout(Duration::from_secs(15))
        .stream_receive_window(VarInt::from_u32(2 * 1024 * 1024))
        .receive_window(VarInt::from_u32(16 * 1024 * 1024))
        .send_window(8 * 1024 * 1024)
        .build()
}

/// 看门狗重连退避：第 n 次连续失败后等待 min(cap, base*2^n) + 抖动。
/// 用 SystemTime 纳秒做抖动，避免引入 rand 依赖。
pub fn backoff_delay(consecutive_failures: u32, now_nanos: u128) -> Duration {
    const BASE_MS: u128 = 1_000;
    const CAP_MS: u128 = 30_000;
    let exp = BASE_MS
        .checked_shl(consecutive_failures.min(6))
        .unwrap_or(CAP_MS);
    let base = std::cmp::min(exp, CAP_MS);
    let jitter = now_nanos % 1_000; // 0..1000 ms
    Duration::from_millis((base + jitter) as u64)
}

/// B 端生成的凭证：A 端凭此接入。
///
/// 只携带 node_id（PublicKey 字符串）和 token —— iroh 会通过 N0 中继网络
/// 根据 node id 自动发现并打洞连接 B，无需手动交换地址。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// B 端的 EndpointId（PublicKey 字符串）
    pub node_id: String,
    /// 访问令牌，防止知道 node id 的第三方盗用隧道
    pub token: String,
}

/// 常量时间比较令牌，避免计时侧信道泄露正确令牌的前缀。
/// 令牌长度本身不是秘密，因此长度不匹配时直接返回。
pub fn token_ok(expected: &str, got: &str) -> bool {
    let (e, g) = (expected.as_bytes(), got.as_bytes());
    if e.len() != g.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..e.len() {
        diff |= e[i] ^ g[i];
    }
    diff == 0
}

/// B 端目标访问策略：限制 token 持有者可拨号的内网范围。CIDR 在启动时解析一次。
#[derive(Debug, Clone, Default)]
pub struct TargetPolicy {
    nets: Vec<IpNet>,
    ports: Vec<u16>,
}

impl TargetPolicy {
    /// 从配置的字符串/端口列表构建；解析失败的 CIDR 会被记日志后跳过。
    pub fn from_config(allow_networks: &[String], allow_ports: &[u16]) -> Self {
        let nets = allow_networks
            .iter()
            .filter_map(|s| match s.parse::<IpNet>() {
                Ok(n) => Some(n),
                Err(_) => {
                    tracing::warn!(cidr = %s, "无法解析允许网段，已忽略");
                    None
                }
            })
            .collect();
        TargetPolicy {
            nets,
            ports: allow_ports.to_vec(),
        }
    }

    /// 允许全部（默认）。
    pub fn allow_all() -> Self {
        TargetPolicy::default()
    }

    /// 解析目标并返回**允许拨号的具体地址集合**（只解析这一次）。
    ///
    /// 关键：调用方必须直接拨号本函数返回的 `SocketAddr`，不要再用 host 字符串重新解析，
    /// 否则会重新引入 DNS 重绑定（TOCTOU）缺口——两次解析之间目标可能被换成白名单外的 IP。
    pub async fn resolve_allowed(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<Vec<SocketAddr>, String> {
        if !self.port_allowed(port) {
            return Err(format!("目标端口 {port} 不在允许列表"));
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("解析 {host} 失败: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("解析 {host} 无结果"));
        }
        if self.nets.is_empty() {
            return Ok(addrs);
        }
        let allowed: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|sa| self.ip_allowed(sa.ip()))
            .collect();
        if allowed.is_empty() {
            return Err(format!("{host} 解析结果均不在允许网段"));
        }
        Ok(allowed)
    }

    /// 端口是否允许（纯函数，便于测试）。
    pub fn port_allowed(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }

    /// 某 IP 是否落在允许网段内（纯函数，便于测试）。未配网段时全部允许。
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.nets.is_empty() || self.nets.iter().any(|n| n.contains(&ip))
    }
}

/// 单个客户（租户）的运行期视图：token + 策略 + 每客户并发上限。
pub struct ClientPolicy {
    pub id: String,
    token: String,
    pub policy: TargetPolicy,
    /// 每客户最大并发隧道数；None = 不限。
    sem: Option<Arc<Semaphore>>,
}

/// 多租户客户端注册表：按 token 常量时间匹配到具体客户。
pub struct ClientRegistry {
    clients: Vec<ClientPolicy>,
}

impl ClientRegistry {
    /// 从归一化后的客户配置构建。吊销的客户会被跳过（等于拒绝接入）。
    pub fn from_configs(clients: &[config::ClientCred]) -> Self {
        let clients = clients
            .iter()
            .filter(|c| !c.revoked && !c.token.is_empty())
            .map(|c| ClientPolicy {
                id: c.id.clone(),
                token: c.token.clone(),
                policy: TargetPolicy::from_config(&c.allow_networks, &c.allow_ports),
                sem: (c.max_streams > 0).then(|| Arc::new(Semaphore::new(c.max_streams))),
            })
            .collect();
        ClientRegistry { clients }
    }

    /// 按 token 认证。为避免"命中位置"计时侧信道，始终遍历全部客户。
    pub fn authenticate(&self, token: &str) -> Option<&ClientPolicy> {
        let mut found = None;
        for c in &self.clients {
            if token_ok(&c.token, token) {
                found = Some(c);
            }
        }
        found
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

/// 审计事件。序列化为一行 JSON，写入 tracing（target="audit"）与可选文件。
#[derive(Serialize)]
pub struct AuditEvent<'a> {
    /// unix 毫秒时间戳（不引入日期库依赖）
    pub ts_ms: u128,
    /// 客户标识（未认证时为 "-"）
    pub client_id: &'a str,
    /// 对端 node id
    pub peer: &'a str,
    /// 目标 host:port
    pub target: &'a str,
    /// 结果：ok / denied_token / denied_target / over_limit / dial_failed / dial_timeout
    pub result: &'a str,
    /// 附加信息
    pub detail: &'a str,
}

/// 审计日志汇聚器：事件同时打到 tracing 和（可选）后台文件写入任务，避免阻塞运行时。
#[derive(Clone)]
pub struct Audit {
    tx: Option<mpsc::UnboundedSender<String>>,
}

impl Audit {
    pub fn disabled() -> Self {
        Audit { tx: None }
    }

    /// 打开审计文件并启动后台追加任务。必须在 tokio 运行时内调用。
    pub fn to_file(path: &str) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let path = path.to_string();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await;
            let mut file = match file {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(error = %e, path = %path, "打开审计日志失败，审计仅输出到 tracing");
                    return;
                }
            };
            while let Some(line) = rx.recv().await {
                if file.write_all(line.as_bytes()).await.is_err()
                    || file.write_all(b"\n").await.is_err()
                {
                    break;
                }
                let _ = file.flush().await;
            }
        });
        Audit { tx: Some(tx) }
    }

    pub fn record(&self, ev: &AuditEvent<'_>) {
        let line = serde_json::to_string(ev).unwrap_or_default();
        tracing::info!(target: "audit", client_id = ev.client_id, peer = ev.peer, target = ev.target, result = ev.result, "audit");
        if let Some(tx) = &self.tx {
            let _ = tx.send(line);
        }
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// 带多个 AtomicU64 计数器的单向拷贝（每块同时累加到所有计数器，便于同时喂给
/// 每映射统计与全局 metrics）。缓冲 64KB 提升大流量吞吐。
pub async fn copy_count<R, W>(mut r: R, mut w: W, counters: &[&AtomicU64]) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
        for c in counters {
            c.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
    Ok(total)
}

/// B 端处理一条流所需的共享上下文。
pub struct ServeCtx {
    pub registry: Arc<ClientRegistry>,
    pub metrics: Arc<Metrics>,
    pub audit: Audit,
    pub dial_timeout: Duration,
    /// 对端 node id 字符串（审计用）
    pub peer: String,
}

/// B 端：处理一条隧道流 —— 读握手头、认证 token、按策略解析并校验目标、
/// 在内网拨号（带超时、直连已校验地址）、双向转发。
pub async fn serve_stream<W, R>(send: W, recv: R, ctx: &ServeCtx) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut send = send;
    let mut recv = recv;
    let m = &ctx.metrics;

    let req = proto::read_open(&mut recv).await?;
    let target = format!("{}:{}", req.host, req.port);

    // 1) 认证
    let client = match ctx.registry.authenticate(&req.token) {
        Some(c) => c,
        None => {
            Metrics::inc(&m.handshake_denied);
            Metrics::inc(&m.tunnels_failed);
            ctx.audit.record(&AuditEvent {
                ts_ms: now_ms(),
                client_id: "-",
                peer: &ctx.peer,
                target: &target,
                result: "denied_token",
                detail: "unknown or revoked token",
            });
            proto::write_status(&mut send, proto::STATUS_ERR, "bad token").await?;
            bail!("bad token");
        }
    };

    // 2) 每客户并发上限
    let _permit = match &client.sem {
        Some(sem) => match sem.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                Metrics::inc(&m.over_limit);
                Metrics::inc(&m.tunnels_failed);
                ctx.audit.record(&AuditEvent {
                    ts_ms: now_ms(),
                    client_id: &client.id,
                    peer: &ctx.peer,
                    target: &target,
                    result: "over_limit",
                    detail: "per-client stream limit reached",
                });
                proto::write_status(&mut send, proto::STATUS_ERR, "over concurrency limit").await?;
                bail!("over limit for client {}", client.id);
            }
        },
        None => None,
    };

    // 3) 解析并校验目标（只解析一次，随后直接拨返回的地址）
    let allowed = match client.policy.resolve_allowed(&req.host, req.port).await {
        Ok(a) => a,
        Err(reason) => {
            Metrics::inc(&m.target_denied);
            Metrics::inc(&m.tunnels_failed);
            tracing::warn!(client = %client.id, host = %req.host, port = req.port, %reason, "目标被策略拒绝");
            ctx.audit.record(&AuditEvent {
                ts_ms: now_ms(),
                client_id: &client.id,
                peer: &ctx.peer,
                target: &target,
                result: "denied_target",
                detail: &reason,
            });
            proto::write_status(&mut send, proto::STATUS_ERR, &reason).await?;
            bail!(reason);
        }
    };

    // 4) 拨号：仅拨已校验地址，带超时，逐个尝试
    let mut tcp = None;
    let mut last_err = String::from("no address");
    let mut timed_out = false;
    for sa in &allowed {
        match tokio::time::timeout(ctx.dial_timeout, TcpStream::connect(sa)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last_err = e.to_string(),
            Err(_) => {
                timed_out = true;
                last_err = format!("拨号 {sa} 超时");
            }
        }
    }
    let tcp = match tcp {
        Some(t) => t,
        None => {
            if timed_out {
                Metrics::inc(&m.dial_timeout);
            } else {
                Metrics::inc(&m.dial_failed);
            }
            Metrics::inc(&m.tunnels_failed);
            ctx.audit.record(&AuditEvent {
                ts_ms: now_ms(),
                client_id: &client.id,
                peer: &ctx.peer,
                target: &target,
                result: if timed_out {
                    "dial_timeout"
                } else {
                    "dial_failed"
                },
                detail: &last_err,
            });
            proto::write_status(&mut send, proto::STATUS_ERR, &last_err).await?;
            bail!(last_err);
        }
    };

    proto::write_status(&mut send, proto::STATUS_OK, "").await?;
    m.tunnel_open();
    ctx.audit.record(&AuditEvent {
        ts_ms: now_ms(),
        client_id: &client.id,
        peer: &ctx.peer,
        target: &target,
        result: "ok",
        detail: "",
    });

    let (mut t_read, mut t_write) = tokio::io::split(tcp);
    // 优雅半关闭：任一方向读到 EOF 后，对该方向的写端 shutdown（QUIC 上等价于 FIN），
    // 另一方向继续透传直到也 EOF。这样 HTTP/1.1 keep-alive 等依赖半关闭的协议能正常工作。
    let up = async {
        copy_count(&mut recv, &mut t_write, &[&m.bytes_rx]).await?;
        t_write.shutdown().await.ok();
        Ok::<_, std::io::Error>(())
    };
    let down = async {
        copy_count(&mut t_read, &mut send, &[&m.bytes_tx]).await?;
        send.shutdown().await.ok();
        Ok::<_, std::io::Error>(())
    };
    let _ = tokio::try_join!(up, down);
    m.tunnel_close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn token_compare_is_constant_time_semantics() {
        assert!(token_ok("abc123", "abc123"));
        assert!(!token_ok("abc123", "abc124"));
        assert!(!token_ok("abc123", "abc"));
        assert!(!token_ok("abc123", "xxxxxxxx"));
    }

    #[test]
    fn target_policy_port_allowed() {
        let p = TargetPolicy::from_config(&[], &[80, 443]);
        assert!(p.port_allowed(80));
        assert!(!p.port_allowed(22));
        assert!(TargetPolicy::allow_all().port_allowed(0));
    }

    #[test]
    fn target_policy_ip_allowed() {
        let p = TargetPolicy::from_config(&["10.0.0.0/8".into(), "127.0.0.0/8".into()], &[]);
        assert!(p.ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(p.ip_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!p.ip_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!p.ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(TargetPolicy::allow_all().ip_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn target_policy_ignores_bad_cidr() {
        let p = TargetPolicy::from_config(&["not-a-cidr".into(), "127.0.0.0/8".into()], &[]);
        assert!(p.ip_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[tokio::test]
    async fn resolve_allowed_filters_to_policy() {
        // 127.0.0.1 允许；端口白名单放行 80
        let p = TargetPolicy::from_config(&["127.0.0.0/8".into()], &[80]);
        let addrs = p.resolve_allowed("127.0.0.1", 80).await.unwrap();
        assert!(
            addrs
                .iter()
                .all(|sa| sa.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        // 端口不在白名单 → 拒绝
        assert!(p.resolve_allowed("127.0.0.1", 22).await.is_err());
    }

    #[tokio::test]
    async fn resolve_allowed_rejects_out_of_network() {
        // 只允许 10/8，解析 127.0.0.1 应被拒（结果不在网段）
        let p = TargetPolicy::from_config(&["10.0.0.0/8".into()], &[]);
        assert!(p.resolve_allowed("127.0.0.1", 6379).await.is_err());
    }

    #[test]
    fn registry_authenticates_and_skips_revoked() {
        let cfgs = vec![
            config::ClientCred {
                id: "alice".into(),
                token: "tok-alice".into(),
                allow_networks: vec![],
                allow_ports: vec![],
                max_streams: 0,
                revoked: false,
            },
            config::ClientCred {
                id: "bob".into(),
                token: "tok-bob".into(),
                allow_networks: vec![],
                allow_ports: vec![],
                max_streams: 0,
                revoked: true,
            },
        ];
        let reg = ClientRegistry::from_configs(&cfgs);
        assert_eq!(reg.len(), 1);
        assert_eq!(
            reg.authenticate("tok-alice").map(|c| c.id.as_str()),
            Some("alice")
        );
        // 已吊销的 bob 不能接入
        assert!(reg.authenticate("tok-bob").is_none());
        assert!(reg.authenticate("nope").is_none());
    }

    #[tokio::test]
    async fn copy_count_increments_all_counters() {
        let a = AtomicU64::new(0);
        let b = AtomicU64::new(0);
        let n = copy_count(&[1u8, 2, 3, 4][..], tokio::io::sink(), &[&a, &b])
            .await
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(a.load(Ordering::Relaxed), 4);
        assert_eq!(b.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn backoff_grows_then_caps_with_jitter() {
        let d0 = backoff_delay(0, 0);
        let d3 = backoff_delay(3, 0);
        let d_big = backoff_delay(20, 0);
        assert!(d3 > d0, "应随失败次数增长");
        assert!(d_big <= Duration::from_millis(31_000));
        assert!(d_big >= Duration::from_millis(30_000));
    }
}
