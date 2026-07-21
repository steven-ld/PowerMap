//! 隧道共享协议：A 端与 B 端在 iroh QUIC 双向流上的握手格式。
//!
//! 流程：
//! 1. A 打开一条 bi 流，先发送握手头（2 字节大端长度 + JSON）：令牌 + 目标地址
//! 2. B 校验令牌、连接目标，回 1 字节状态码（0 = 成功）
//! 3. 之后流上就是透传的 TCP 数据

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 自定义协议的 ALPN 标识
pub const ALPN: &[u8] = b"/powermap/tcp/0";

/// 握手头最大长度，防止恶意对端发送超大头部耗尽内存
pub const MAX_HEADER_LEN: u16 = 4096;

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;

/// A 端发起的"打开隧道"请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    /// 访问令牌，由 B 端生成，防止知道 Node ID 的第三方盗用隧道
    pub token: String,
    /// 目标主机（B 端内网中的 IP / 主机名，例如 192.168.1.101）
    pub host: String,
    /// 目标端口
    pub port: u16,
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
