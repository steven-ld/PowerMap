//! Pure health classification for configured mappings.

use serde::Serialize;

/// Operator-facing state for one mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Degraded,
    Stopped,
    Unknown,
}

/// Runtime facts required to classify a mapping without performing any I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingInput {
    pub enabled: bool,
    pub listener_active: bool,
    pub last_tunnel_failed: bool,
}

/// Health classification for an input mapping, retained in input order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MappingHealth {
    pub health: Health,
}

/// Aggregate health counts and deterministic, actionable next steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub total: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub stopped: usize,
    pub unknown: usize,
    pub mappings: Vec<MappingHealth>,
    pub recommendations: Vec<&'static str>,
}

/// Summarize mapping health using only the supplied runtime facts.
pub fn summarize(inputs: Vec<MappingInput>) -> Summary {
    let mut summary = Summary {
        total: inputs.len(),
        healthy: 0,
        degraded: 0,
        stopped: 0,
        unknown: 0,
        mappings: Vec::with_capacity(inputs.len()),
        recommendations: Vec::new(),
    };

    for input in inputs {
        let health = classify(input);
        match health {
            Health::Healthy => summary.healthy += 1,
            Health::Degraded => summary.degraded += 1,
            Health::Stopped => summary.stopped += 1,
            Health::Unknown => summary.unknown += 1,
        }
        summary.mappings.push(MappingHealth { health });
    }

    if summary.stopped > 0 {
        summary
            .recommendations
            .push("Restart the mapping and verify its local listener can bind.");
    }
    if summary.degraded > 0 {
        summary
            .recommendations
            .push("Check the remote peer connection and retry the mapping.");
    }
    if summary.unknown > 0 {
        summary
            .recommendations
            .push("Enable the mapping when it is ready to accept traffic.");
    }

    summary
}

fn classify(input: MappingInput) -> Health {
    if !input.enabled {
        Health::Unknown
    } else if !input.listener_active {
        Health::Stopped
    } else if input.last_tunnel_failed {
        Health::Degraded
    } else {
        Health::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::{Health, MappingInput, summarize};

    #[test]
    fn disabled_mapping_is_unknown_with_enable_recommendation() {
        let summary = summarize(vec![MappingInput {
            enabled: false,
            listener_active: false,
            last_tunnel_failed: false,
        }]);

        assert_eq!(summary.total, 1);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.healthy, 0);
        assert_eq!(
            summary.recommendations,
            vec!["Enable the mapping when it is ready to accept traffic."]
        );
        assert_eq!(summary.mappings[0].health, Health::Unknown);
    }

    #[test]
    fn listener_failure_marks_mapping_stopped() {
        let summary = summarize(vec![MappingInput {
            enabled: true,
            listener_active: false,
            last_tunnel_failed: false,
        }]);

        assert_eq!(summary.stopped, 1);
        assert_eq!(summary.mappings[0].health, Health::Stopped);
        assert_eq!(
            summary.recommendations,
            vec!["Restart the mapping and verify its local listener can bind."]
        );
    }

    #[test]
    fn tunnel_failure_marks_mapping_degraded() {
        let summary = summarize(vec![MappingInput {
            enabled: true,
            listener_active: true,
            last_tunnel_failed: true,
        }]);

        assert_eq!(summary.degraded, 1);
        assert_eq!(summary.mappings[0].health, Health::Degraded);
        assert_eq!(
            summary.recommendations,
            vec!["Check the remote peer connection and retry the mapping."]
        );
    }

    #[test]
    fn active_mapping_is_healthy_without_recommendations() {
        let summary = summarize(vec![MappingInput {
            enabled: true,
            listener_active: true,
            last_tunnel_failed: false,
        }]);

        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.recommendations, Vec::<&str>::new());
        assert_eq!(summary.mappings[0].health, Health::Healthy);
    }
}
