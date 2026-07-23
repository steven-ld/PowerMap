//! Pure, serializable diagnostic-report construction.
//!
//! The runtime supplies every input, including the timestamp. This keeps report
//! construction deterministic and prevents this module from reading local state.

use serde::{Deserialize, Serialize};

/// Inputs collected by the management runtime for a diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReportInput {
    pub version: String,
    pub transport: TransportSummary,
    pub mappings: MappingCounts,
    pub recent_events: Vec<String>,
    /// Unix epoch timestamp in milliseconds, supplied by the caller.
    pub generated_at_unix_ms: u64,
}

/// Connection facts suitable for an operator-facing report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportSummary {
    pub kind: String,
    pub connected: bool,
    pub relay: Option<String>,
    pub rtt_ms: Option<u64>,
}

/// Counts of configured mappings at report generation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingCounts {
    pub total: usize,
    pub enabled: usize,
    pub disabled: usize,
}

/// A report safe to serialize or download from the local management console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub version: String,
    pub transport: TransportSummary,
    pub mappings: MappingCounts,
    pub recent_events: Vec<String>,
    pub generated_at_unix_ms: u64,
}

/// Builds a deterministic report from runtime-supplied facts.
pub fn build(input: ReportInput) -> Report {
    Report {
        version: input.version,
        transport: TransportSummary {
            kind: input.transport.kind,
            connected: input.transport.connected,
            relay: input.transport.relay.map(|relay| redact_text(&relay)),
            rtt_ms: input.transport.rtt_ms,
        },
        mappings: input.mappings,
        recent_events: input
            .recent_events
            .into_iter()
            .map(|event| redact_text(&event))
            .collect(),
        generated_at_unix_ms: input.generated_at_unix_ms,
    }
}

fn redact_text(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    let mut redact_next = false;

    while let Some(index) = rest.find(char::is_whitespace) {
        let word = &rest[..index];
        if redact_next {
            result.push_str("<redacted>");
            redact_next = false;
        } else {
            result.push_str(&redact_word(word));
            redact_next = word.eq_ignore_ascii_case("bearer");
        }
        let whitespace_end = rest[index..]
            .find(|character: char| !character.is_whitespace())
            .map(|offset| index + offset)
            .unwrap_or(rest.len());
        result.push_str(&rest[index..whitespace_end]);
        rest = &rest[whitespace_end..];
    }

    if redact_next && !rest.is_empty() {
        result.push_str("<redacted>");
    } else {
        result.push_str(&redact_word(rest));
    }
    result
}

fn redact_word(word: &str) -> String {
    if is_path_like(word) {
        return "<redacted-path>".into();
    }

    if is_jwt_like(word) {
        return "<redacted>".into();
    }

    if let Some((key, value)) = word.split_once('=')
        && is_sensitive_key(key)
        && !value.is_empty()
    {
        return format!("{key}=<redacted>");
    }

    if let Some((key, value)) = word.split_once(':')
        && is_sensitive_key(key)
        && !value.is_empty()
    {
        return format!("{key}:<redacted>");
    }

    word.into()
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key.trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .to_ascii_lowercase()
            .as_str(),
        "token"
            | "access_token"
            | "auth"
            | "authorization"
            | "credential"
            | "secret"
            | "password"
            | "api_key"
            | "apikey"
    )
}

fn is_path_like(word: &str) -> bool {
    let word =
        word.trim_matches(|character: char| matches!(character, '"' | '\'' | '(' | ')' | ','));
    word.starts_with('/')
        || word.starts_with("~/")
        || (word.len() > 3
            && word.as_bytes()[0].is_ascii_alphabetic()
            && word.as_bytes()[1] == b':'
            && matches!(word.as_bytes()[2], b'/' | b'\\'))
}

fn is_jwt_like(word: &str) -> bool {
    let mut segments = word.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    let Some(second) = segments.next() else {
        return false;
    };
    let Some(third) = segments.next() else {
        return false;
    };

    segments.next().is_none()
        && [first, second, third]
            .iter()
            .all(|segment| segment.len() >= 8 && segment.bytes().all(is_token_character))
}

fn is_token_character(character: u8) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::{MappingCounts, ReportInput, TransportSummary, build};

    #[test]
    fn redacts_token_like_and_path_like_event_text() {
        let report = build(ReportInput {
            version: "0.6.0".into(),
            transport: TransportSummary {
                kind: "relay".into(),
                connected: true,
                relay: Some("relay.example.test".into()),
                rtt_ms: Some(42),
            },
            mappings: MappingCounts {
                total: 2,
                enabled: 1,
                disabled: 1,
            },
            recent_events: vec![
                "connection failed: token=super-secret-token".into(),
                "could not read /Users/alice/.config/powermap/config.toml".into(),
            ],
            generated_at_unix_ms: 1_753_274_400_000,
        });

        assert_eq!(
            report.recent_events[0],
            "connection failed: token=<redacted>"
        );
        assert_eq!(report.recent_events[1], "could not read <redacted-path>");
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("super-secret-token"));
        assert!(!serialized.contains("/Users/alice"));
    }

    #[test]
    fn preserves_caller_supplied_report_facts_deterministically() {
        let input = ReportInput {
            version: "0.6.0".into(),
            transport: TransportSummary {
                kind: "direct".into(),
                connected: true,
                relay: None,
                rtt_ms: Some(7),
            },
            mappings: MappingCounts {
                total: 3,
                enabled: 2,
                disabled: 1,
            },
            recent_events: vec!["mapping started".into()],
            generated_at_unix_ms: 1_753_274_460_000,
        };

        let first = build(input.clone());
        assert_eq!(first, build(input));
        assert_eq!(first.generated_at_unix_ms, 1_753_274_460_000);
        assert_eq!(first.mappings.total, 3);
    }

    #[test]
    fn redacts_bearer_credentials() {
        let report = build(ReportInput {
            version: "0.6.0".into(),
            transport: TransportSummary {
                kind: "disconnected".into(),
                connected: false,
                relay: None,
                rtt_ms: None,
            },
            mappings: MappingCounts {
                total: 0,
                enabled: 0,
                disabled: 0,
            },
            recent_events: vec!["Authorization: Bearer a-very-private-access-token".into()],
            generated_at_unix_ms: 1_753_274_520_000,
        });

        assert_eq!(report.recent_events, ["Authorization: Bearer <redacted>"]);
    }
}
