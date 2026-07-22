//! 隧道共享协议：A 端与 B 端在 iroh QUIC 双向流上的握手格式。
//!
//! 流程：
//! 1. 发起端打开一条 bi 流，先发送握手头（2 字节大端长度 + JSON）：令牌 + 目标地址 + 隧道类型
//! 2. 接收端校验令牌、连接目标，回 1 字节状态码（0 = 成功）
//! 3. 之后流上是透传数据：
//!    - TCP 隧道：裸字节流双向透传；
//!    - UDP 隧道：每个数据报前缀 2 字节大端长度，形成有边界的报文序列。
//!
//! 正向隧道由 A（用户端）发起、B（穿透端）拨号内网目标；反向隧道由 B 发起、
//! A 拨号自己一侧的目标，两者复用同一套握手，仅 ALPN 与拨号策略不同。

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 隧道 ALPN。正向与反向隧道复用同一条 A→B 连接（QUIC 双向流可双向开），
/// 因此只需一个 ALPN；反向由 B 在既有连接上开流、A 接受并按自身白名单回拨。
pub const ALPN: &[u8] = b"/powermap/tcp/0";

/// 握手头最大长度，防止恶意对端发送超大头部耗尽内存
pub const MAX_HEADER_LEN: u16 = 4096;

/// UDP 数据报单帧最大长度（略大于常见 MTU 与 IPv4/IPv6 理论上限的实际取值）。
/// 超过此长度的写入会被拒绝，避免异常对端撑爆缓冲。
pub const MAX_DATAGRAM_LEN: u16 = u16::MAX;

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;

/// 隧道承载的传输类型。旧端不发送此字段时默认 Tcp，保持线上兼容。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    #[default]
    Tcp,
    Udp,
}

impl TunnelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelKind::Tcp => "tcp",
            TunnelKind::Udp => "udp",
        }
    }
}

/// 发起端的"打开隧道"请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    /// 访问令牌，由接收端生成，防止知道 Node ID 的第三方盗用隧道
    pub token: String,
    /// 目标主机（接收端一侧能访问到的 IP / 主机名，例如 192.168.1.101）
    pub host: String,
    /// 目标端口
    pub port: u16,
    /// 隧道类型（tcp / udp）。旧端省略时按 tcp 处理。
    #[serde(default)]
    pub kind: TunnelKind,
    /// 是否为反向注册流：A 端在既有连接上开一条流、置此位并带 token，
    /// B 端据此把「连接 → 客户」关联起来，随后在该连接上开反向隧道流。
    /// 旧端省略时为 false，即普通正向隧道，保持兼容。
    #[serde(default)]
    pub register: bool,
}

pub async fn write_open<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    req: &OpenRequest,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_HEADER_LEN as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "handshake header too large",
        ));
    }
    w.write_all(&(body.len() as u16).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_open<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<OpenRequest> {
    let len = r.read_u16().await?;
    if len > MAX_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "handshake header too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// B 端回写状态：0 表示成功，其余为错误码 + 可选错误信息
pub async fn write_status<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    code: u8,
    msg: &str,
) -> std::io::Result<()> {
    w.write_u8(code).await?;
    if code != STATUS_OK {
        let body = msg.as_bytes();
        let len = body.len().min(u16::MAX as usize) as u16;
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(&body[..len as usize]).await?;
    }
    w.flush().await?;
    Ok(())
}

/// A 端读取状态；Ok(Ok(())) 表示隧道已建立，可以开始透传
pub async fn read_status<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> std::io::Result<Result<(), String>> {
    let code = r.read_u8().await?;
    if code == STATUS_OK {
        return Ok(Ok(()));
    }
    let len = r.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Err(String::from_utf8_lossy(&buf).into_owned()))
}

/// 在 QUIC 流上写一个带 2 字节长度前缀的 UDP 数据报。
/// 超过 `MAX_DATAGRAM_LEN` 的报文被拒绝，避免异常对端撑爆缓冲。
pub async fn write_datagram<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.len() > MAX_DATAGRAM_LEN as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "datagram too large",
        ));
    }
    w.write_all(&(payload.len() as u16).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// 从 QUIC 流上读一个带 2 字节长度前缀的 UDP 数据报到 `buf`，返回报文长度。
/// 流干净结束（读长度时 EOF）返回 `Ok(None)`，供调用方区分正常关闭与半截帧。
pub async fn read_datagram<R: AsyncReadExt + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<usize>> {
    let mut len_bytes = [0u8; 2];
    match r.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(len_bytes) as usize;
    buf.resize(len, 0);
    r.read_exact(buf).await?;
    Ok(Some(len))
}

/// 简单的十六进制编码/解码，用于密钥与令牌的文本表示
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
