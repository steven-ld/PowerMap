//! Bounded discovery of services listening on this computer.
//!
//! This is intentionally not a network scanner: candidates are compile-time
//! loopback ports only, each probe has a short timeout, and no banner data is
//! read or retained.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde::Serialize;
use tokio::net::TcpStream;

const PROBE_TIMEOUT: Duration = Duration::from_millis(180);
const CANDIDATES: &[(u16, &str)] = &[
    (22, "SSH"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3000, "Web 开发服务"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8000, "Web 服务"),
    (8080, "Web 服务"),
    (8088, "PowerMap 控制台"),
    (8443, "HTTPS"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalService {
    pub address: String,
    pub port: u16,
    pub label: &'static str,
}

/// Returns only confirmed listeners on this machine's loopback interfaces.
pub async fn discover() -> Vec<LocalService> {
    let mut found = Vec::new();
    for &(port, label) in CANDIDATES {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        let address = if is_open(v4).await {
            Some("127.0.0.1")
        } else if is_open(v6).await {
            Some("::1")
        } else {
            None
        };
        if let Some(address) = address {
            found.push(LocalService {
                address: address.into(),
                port,
                label,
            });
        }
    }
    found
}

async fn is_open(addr: SocketAddr) -> bool {
    tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
        .await
        .is_ok_and(|result| result.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_only_returns_fixed_loopback_candidates() {
        let services = discover().await;
        assert!(services.iter().all(|service| matches!(
            service.address.as_str(),
            "127.0.0.1" | "::1"
        )
            && CANDIDATES.iter().any(|(port, _)| *port == service.port)));
    }
}
