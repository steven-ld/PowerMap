//! Deterministic loopback-only port suggestions.

use serde::Serialize;

const LOOPBACK_HOST: &str = "127.0.0.1";
const MAX_SUGGESTIONS: usize = 5;

/// A local address a mapping may use without exposing a non-loopback interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub host: &'static str,
    pub port: u16,
}

/// Returns up to five available-looking loopback ports without performing a scan.
///
/// Availability is based solely on the caller-supplied `occupied` list. Candidates
/// increase from `preferred` through `65535`; they never wrap into a new range.
pub fn suggest_loopback(preferred: u16, occupied: &[u16]) -> Vec<Suggestion> {
    (preferred.max(1)..=u16::MAX)
        .filter(|port| !occupied.contains(port))
        .take(MAX_SUGGESTIONS)
        .map(|port| Suggestion {
            host: LOOPBACK_HOST,
            port,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::suggest_loopback;

    #[test]
    fn returns_the_preferred_loopback_port_when_available() {
        let suggestions = suggest_loopback(8080, &[]);

        assert_eq!(suggestions.len(), 5);
        assert_eq!(suggestions[0].host, "127.0.0.1");
        assert_eq!(suggestions[0].port, 8080);
    }

    #[test]
    fn skips_an_occupied_preferred_port() {
        let suggestions = suggest_loopback(8080, &[8080, 8082]);

        assert_eq!(
            suggestions
                .iter()
                .map(|suggestion| suggestion.port)
                .collect::<Vec<_>>(),
            vec![8081, 8083, 8084, 8085, 8086]
        );
    }

    #[test]
    fn stops_at_the_upper_port_boundary_without_wrapping() {
        let suggestions = suggest_loopback(65_534, &[65_535]);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].port, 65_534);
        assert!(
            suggestions
                .iter()
                .all(|suggestion| suggestion.host == "127.0.0.1")
        );
    }
}
