//! Read-only connection diagnostics for the local management API.
//!
//! Recommendations intentionally describe only what the current link proves;
//! they do not attempt to infer a NAT type from a single observation.

use serde::Serialize;

/// Inputs collected from the live connection and local configuration.
#[derive(Debug, Clone)]
pub struct Observation {
    pub configured: bool,
    pub connected: bool,
    pub path: Option<&'static str>,
    pub rtt_ms: Option<u64>,
    pub relay: Option<String>,
    pub peer_ips: Vec<String>,
}

/// Stable, client-facing diagnostic result returned by the management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// `direct`, `relay`, or `disconnected`.
    pub transport: &'static str,
    pub connected_peer_ips: Vec<String>,
    pub relay: Option<String>,
    pub rtt_ms: Option<u64>,
    pub configuration: ConfigurationPresence,
    /// Guidance limited to facts observable from this node's current link.
    pub nat_guidance: &'static str,
    /// A stable, human-readable next action for operators.
    pub recommendation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigurationPresence {
    pub credential_configured: bool,
}

impl Snapshot {
    pub fn from_observation(observation: Observation) -> Self {
        let transport = if !observation.connected {
            "disconnected"
        } else if observation.path == Some("direct") {
            "direct"
        } else if observation.path == Some("relay") {
            "relay"
        } else {
            // A live connection without a selected path is still not enough evidence to
            // claim either NAT traversal mode. Present it as unavailable to callers.
            "disconnected"
        };

        let (connected_peer_ips, relay, rtt_ms) = if transport == "disconnected" {
            (Vec::new(), None, None)
        } else {
            (observation.peer_ips, observation.relay, observation.rtt_ms)
        };

        let (nat_guidance, recommendation) = match transport {
            "direct" => (
                "A direct peer path is active; this observation does not indicate a NAT problem.",
                "Keep the current network configuration; the peer connection is direct.",
            ),
            "relay" => (
                "A relay path is active. This does not identify a NAT type; direct traversal is not currently selected.",
                "Keep relay access available. If lower latency matters, verify both networks permit UDP and NAT traversal.",
            ),
            _ if !observation.configured => (
                "NAT cannot be assessed until a configured peer connection is active.",
                "Configure the server credential, then retry the connection.",
            ),
            _ => (
                "NAT cannot be assessed until a peer connection is active.",
                "Verify that the remote node is running and that the configured credential is current, then retry.",
            ),
        };

        Self {
            transport,
            connected_peer_ips,
            relay,
            rtt_ms,
            configuration: ConfigurationPresence {
                credential_configured: observation.configured,
            },
            nat_guidance,
            recommendation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Observation, Snapshot};

    #[test]
    fn unconfigured_node_has_a_stable_setup_recommendation() {
        let snapshot = Snapshot::from_observation(Observation {
            configured: false,
            connected: false,
            path: None,
            rtt_ms: None,
            relay: None,
            peer_ips: vec!["192.0.2.1".into()],
        });

        assert_eq!(snapshot.transport, "disconnected");
        assert!(snapshot.connected_peer_ips.is_empty());
        assert_eq!(
            snapshot.recommendation,
            "Configure the server credential, then retry the connection."
        );
    }

    #[test]
    fn relay_observation_preserves_relay_quality_details() {
        let snapshot = Snapshot::from_observation(Observation {
            configured: true,
            connected: true,
            path: Some("relay"),
            rtt_ms: Some(42),
            relay: Some("relay.example.test".into()),
            peer_ips: vec!["203.0.113.8".into()],
        });

        assert_eq!(snapshot.transport, "relay");
        assert_eq!(snapshot.relay.as_deref(), Some("relay.example.test"));
        assert_eq!(snapshot.rtt_ms, Some(42));
        assert!(
            snapshot
                .nat_guidance
                .contains("does not identify a NAT type")
        );
    }
}
