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
    /// B 端管理员显式发布的候选目标。旧凭证省略此字段时保持兼容。
    #[serde(default)]
    pub published_targets: Vec<config::PublishedTarget>,
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

/// A 端反向映射策略：约束 B 端可让 A 拨号的目标（A 本机或家庭网络）。
///
/// 与正向 `TargetPolicy` 语义**相反**：这里空列表表示**全部拒绝**（deny-all）。
/// 反向隧道会让持有 B 的一方触达 A 侧服务，因此默认不放行任何目标，必须显式列出。
#[derive(Debug, Clone, Default)]
pub struct ReversePolicy {
    enabled: bool,
    nets: Vec<IpNet>,
    ports: Vec<u16>,
}

impl ReversePolicy {
    /// 从 A 端配置构建。`enabled` 为总开关；网段/端口留空即 deny-all。
    pub fn from_config(enabled: bool, allow_networks: &[String], allow_ports: &[u16]) -> Self {
        let nets = allow_networks
            .iter()
            .filter_map(|s| match s.parse::<IpNet>() {
                Ok(n) => Some(n),
                Err(_) => {
                    tracing::warn!(cidr = %s, "反向策略：无法解析 CIDR，已忽略");
                    None
                }
            })
            .collect();
        ReversePolicy {
            enabled,
            nets,
            ports: allow_ports.to_vec(),
        }
    }

    /// 解析目标并返回**允许拨号的具体地址集合**（deny-all：未开启或列表为空时一律拒绝）。
    /// 与正向一样只解析一次，随后直接拨返回的地址，避免 DNS 重绑定（TOCTOU）。
    pub async fn resolve_allowed(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<Vec<SocketAddr>, String> {
        if !self.enabled {
            return Err("反向映射未启用（reverse_enabled = false）".into());
        }
        if self.ports.is_empty() || self.nets.is_empty() {
            return Err(
                "反向映射默认拒绝：需显式配置 reverse_allow_networks 与 reverse_allow_ports".into(),
            );
        }
        if !self.ports.contains(&port) {
            return Err(format!("反向目标端口 {port} 不在 reverse_allow_ports 中"));
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("解析 {host} 失败: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("解析 {host} 无结果"));
        }
        let allowed: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|sa| self.nets.iter().any(|n| n.contains(&sa.ip())))
            .collect();
        if allowed.is_empty() {
            return Err(format!("{host} 解析结果均不在 reverse_allow_networks 内"));
        }
        Ok(allowed)
    }
}

/// A 端处理一条 B 发起的反向隧道流：读握手头、按 A 端 deny-all 策略校验、
/// 拨号 A 一侧目标、双向透传（支持半关闭）。token 无需再验（连接已在注册时认证）。
pub async fn serve_reverse_stream<W, R>(
    send: W,
    recv: R,
    policy: &ReversePolicy,
    dial_timeout: Duration,
    metrics: &Arc<Metrics>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut send = send;
    let mut recv = recv;
    let req = proto::read_open(&mut recv).await?;

    let allowed = match policy.resolve_allowed(&req.host, req.port).await {
        Ok(a) => a,
        Err(reason) => {
            Metrics::inc(&metrics.target_denied);
            Metrics::inc(&metrics.tunnels_failed);
            tracing::warn!(host = %req.host, port = req.port, %reason, "反向目标被 A 端策略拒绝");
            proto::write_status(&mut send, proto::STATUS_ERR, &reason).await?;
            bail!(reason);
        }
    };

    let mut tcp = None;
    let mut last_err = String::from("no address");
    for sa in &allowed {
        match tokio::time::timeout(dial_timeout, TcpStream::connect(sa)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last_err = e.to_string(),
            Err(_) => last_err = format!("拨号 {sa} 超时"),
        }
    }
    let tcp = match tcp {
        Some(t) => t,
        None => {
            Metrics::inc(&metrics.dial_failed);
            Metrics::inc(&metrics.tunnels_failed);
            proto::write_status(&mut send, proto::STATUS_ERR, &last_err).await?;
            bail!(last_err);
        }
    };

    proto::write_status(&mut send, proto::STATUS_OK, "").await?;
    metrics.tunnel_open();

    let (mut t_read, mut t_write) = tokio::io::split(tcp);
    let up = async {
        copy_count(&mut recv, &mut t_write, &[&metrics.bytes_rx]).await?;
        t_write.shutdown().await.ok();
        Ok::<_, std::io::Error>(())
    };
    let down = async {
        copy_count(&mut t_read, &mut send, &[&metrics.bytes_tx]).await?;
        send.shutdown().await.ok();
        Ok::<_, std::io::Error>(())
    };
    let _ = tokio::try_join!(up, down);
    metrics.tunnel_close();
    Ok(())
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

/// B 端：读一条流的握手头并转发（正向隧道）。register 流由 server 层单独处理，
/// 不应走到这里；若误入则拒绝。保留此薄封装供仅需正向的调用方与测试使用。
pub async fn serve_stream<W, R>(mut send: W, mut recv: R, ctx: &ServeCtx) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let req = proto::read_open(&mut recv).await?;
    if req.register {
        proto::write_status(&mut send, proto::STATUS_ERR, "unexpected register stream").await?;
        bail!("unexpected register stream in serve_stream");
    }
    serve_forward(send, recv, req, ctx).await
}

/// B 端正向隧道：认证 token、按策略解析并校验目标、在内网拨号、双向转发。
/// 握手头已由调用方读出并传入，便于 server 层先分流 register / 正向流。
pub async fn serve_forward<W, R>(
    mut send: W,
    recv: R,
    req: proto::OpenRequest,
    ctx: &ServeCtx,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let m = &ctx.metrics;
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

    // 4) 按隧道类型分派：UDP 绑定并连接 UDP 目标；TCP 拨号已校验地址。
    match req.kind {
        proto::TunnelKind::Udp => serve_udp(send, recv, &allowed, ctx, client, &target).await,
        proto::TunnelKind::Tcp => serve_tcp(send, recv, &allowed, ctx, client, &target).await,
    }
}

/// B 端 TCP 隧道：拨号已校验地址（带超时、逐个尝试），双向透传并支持半关闭。
async fn serve_tcp<W, R>(
    mut send: W,
    mut recv: R,
    allowed: &[SocketAddr],
    ctx: &ServeCtx,
    client: &ClientPolicy,
    target: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let m = &ctx.metrics;
    let mut tcp = None;
    let mut last_err = String::from("no address");
    let mut timed_out = false;
    for sa in allowed {
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
                target,
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
        target,
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

/// B 端 UDP 隧道：绑定与目标同族的 UDP socket 并 connect 到第一个已校验地址，
/// 然后在 QUIC 流（长度前缀数据报）与 UDP socket 之间双向搬运数据报。
///
/// UDP 无连接，没有 EOF 概念，因此隧道生命周期由 QUIC 流决定：A 端关闭流（或断开）
/// 时上行结束，进而结束整条隧道；下行方向在流关闭后自然不再写入。
async fn serve_udp<W, R>(
    mut send: W,
    mut recv: R,
    allowed: &[SocketAddr],
    ctx: &ServeCtx,
    client: &ClientPolicy,
    target: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let m = &ctx.metrics;
    // UDP 目标只取第一个已校验地址（已受 allow_networks/allow_ports 约束）。
    let dst = match allowed.first() {
        Some(sa) => *sa,
        None => {
            Metrics::inc(&m.dial_failed);
            Metrics::inc(&m.tunnels_failed);
            proto::write_status(&mut send, proto::STATUS_ERR, "no address").await?;
            bail!("no address");
        }
    };
    // 绑定与目标同族的临时端口，connect 后仅收发该目标，避免误收无关来源。
    let bind_addr: SocketAddr = if dst.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            Metrics::inc(&m.dial_failed);
            Metrics::inc(&m.tunnels_failed);
            let reason = format!("绑定 UDP socket 失败: {e}");
            proto::write_status(&mut send, proto::STATUS_ERR, &reason).await?;
            bail!(reason);
        }
    };
    if let Err(e) = socket.connect(dst).await {
        Metrics::inc(&m.dial_failed);
        Metrics::inc(&m.tunnels_failed);
        let reason = format!("连接 UDP 目标 {dst} 失败: {e}");
        proto::write_status(&mut send, proto::STATUS_ERR, &reason).await?;
        bail!(reason);
    }

    proto::write_status(&mut send, proto::STATUS_OK, "").await?;
    m.tunnel_open();
    ctx.audit.record(&AuditEvent {
        ts_ms: now_ms(),
        client_id: &client.id,
        peer: &ctx.peer,
        target,
        result: "ok",
        detail: "udp",
    });

    let socket = Arc::new(socket);
    let result = relay_udp(&mut send, &mut recv, &socket, &m.bytes_tx, &m.bytes_rx).await;
    m.tunnel_close();
    result
}

/// 在 QUIC 流与已 connect 的 UDP socket 之间双向搬运数据报，直到流结束或出错。
/// `stream_tx` 计入下行（socket→流），`stream_rx` 计入上行（流→socket）。
pub async fn relay_udp<W, R>(
    send: &mut W,
    recv: &mut R,
    socket: &Arc<tokio::net::UdpSocket>,
    stream_tx: &AtomicU64,
    stream_rx: &AtomicU64,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    // 上行：从 QUIC 流读长度前缀数据报，发到 UDP 目标。
    let up = async {
        let mut buf = Vec::with_capacity(2048);
        loop {
            match proto::read_datagram(recv, &mut buf).await? {
                None => break, // 流干净结束
                Some(n) => {
                    socket.send(&buf[..n]).await?;
                    stream_rx.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        Ok::<_, std::io::Error>(())
    };
    // 下行：从 UDP 目标收包，加长度前缀写回 QUIC 流。
    let down = async {
        let mut buf = vec![0u8; proto::MAX_DATAGRAM_LEN as usize];
        loop {
            let n = socket.recv(&mut buf).await?;
            proto::write_datagram(send, &buf[..n]).await?;
            stream_tx.fetch_add(n as u64, Ordering::Relaxed);
        }
        #[allow(unreachable_code)]
        Ok::<_, std::io::Error>(())
    };
    // 上行结束（流关闭）即结束整条隧道；下行随任务取消停止。
    tokio::select! {
        r = up => { r?; }
        r = down => { r?; }
    }
    send.shutdown().await.ok();
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
                published_targets: vec![],
                reverse: vec![],
                max_streams: 0,
                revoked: false,
            },
            config::ClientCred {
                id: "bob".into(),
                token: "tok-bob".into(),
                allow_networks: vec![],
                allow_ports: vec![],
                published_targets: vec![],
                reverse: vec![],
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

    #[tokio::test]
    async fn reverse_policy_denies_by_default() {
        // 未启用：一律拒绝。
        let disabled = ReversePolicy::from_config(false, &["127.0.0.0/8".into()], &[80]);
        assert!(disabled.resolve_allowed("127.0.0.1", 80).await.is_err());

        // 启用但网段/端口为空：deny-all。
        let empty = ReversePolicy::from_config(true, &[], &[]);
        assert!(empty.resolve_allowed("127.0.0.1", 80).await.is_err());
        let no_ports = ReversePolicy::from_config(true, &["127.0.0.0/8".into()], &[]);
        assert!(no_ports.resolve_allowed("127.0.0.1", 80).await.is_err());
    }

    #[tokio::test]
    async fn reverse_policy_allows_only_explicit_target() {
        let p = ReversePolicy::from_config(true, &["127.0.0.0/8".into()], &[80]);
        // 端口与网段都命中才放行。
        let addrs = p.resolve_allowed("127.0.0.1", 80).await.unwrap();
        assert!(addrs.iter().all(|sa| sa.ip().is_loopback()));
        // 端口不在白名单：拒绝。
        assert!(p.resolve_allowed("127.0.0.1", 22).await.is_err());
        // 网段外的目标：拒绝（8.8.8.8 不在 127/8）。
        assert!(p.resolve_allowed("8.8.8.8", 80).await.is_err());
    }

    #[tokio::test]
    async fn udp_relay_round_trips_datagrams_through_a_stream() {
        // 起一个 UDP echo 目标。
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            for _ in 0..2 {
                let (n, from) = target.recv_from(&mut buf).await.unwrap();
                target.send_to(&buf[..n], from).await.unwrap();
            }
        });

        // 用内存双工模拟 A 侧的 QUIC 流：一端喂上行数据报，另一端读下行。
        let (a_side, b_side) = tokio::io::duplex(64 * 1024);
        let (mut a_read, mut a_write) = tokio::io::split(a_side);
        let (b_read, b_write) = tokio::io::split(b_side);

        // B 侧：绑定并 connect UDP echo 目标，跑 relay。
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(target_addr).await.unwrap();
        let sock = Arc::new(sock);
        let tx = AtomicU64::new(0);
        let rx = AtomicU64::new(0);
        let relay = async {
            let mut w = b_write;
            let mut r = b_read;
            let _ = relay_udp(&mut w, &mut r, &sock, &tx, &rx).await;
        };

        let client = async {
            // 上行发一个数据报。
            proto::write_datagram(&mut a_write, b"ping").await.unwrap();
            // 读回下行（echo）。
            let mut buf = Vec::new();
            let n = proto::read_datagram(&mut a_read, &mut buf).await.unwrap();
            assert_eq!(n, Some(4));
            assert_eq!(&buf[..], b"ping");
            // 关闭上行流，结束 relay。
            a_write.shutdown().await.ok();
        };

        tokio::join!(relay, client);
        assert_eq!(rx.load(Ordering::Relaxed), 4); // 上行计入 rx
        assert_eq!(tx.load(Ordering::Relaxed), 4); // 下行计入 tx
    }
}
