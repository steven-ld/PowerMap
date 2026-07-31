//! Runtime policy for ordered relay failover.
//!
//! iroh selects the lowest-latency relay within one `RelayMap`; that is useful for a peer set,
//! but cannot express "try this managed relay first". PowerMap therefore starts with only the
//! primary map and inserts the iroh default map after primary registration fails.

use std::time::Duration;

use iroh::{Endpoint, Watcher};
use tokio_util::sync::CancellationToken;

use crate::config;

/// Allow a net report plus a relay handshake before adding the secondary relay set.
pub const PRIMARY_RELAY_GRACE: Duration = Duration::from_secs(15);

/// Wait until the primary relay set cannot keep the endpoint registered.
///
/// Returns `true` once the iroh fallback should be installed, and `false` when shutdown wins.
pub async fn wait_for_primary_relay_failure(
    endpoint: Endpoint,
    grace: Duration,
    cancel: CancellationToken,
) -> bool {
    let mut watcher = endpoint.home_relay_status();
    let initial = watcher.get();
    let mut was_connected = initial.iter().any(|status| status.is_connected());
    if initial_primary_relay_failed(
        was_connected,
        initial.iter().any(|status| status.last_error().is_some()),
    ) {
        return true;
    }

    let timeout = tokio::time::sleep(grace);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return false,
            _ = &mut timeout, if !was_connected => return true,
            changed = watcher.updated() => {
                let Ok(statuses) = changed else {
                    return false;
                };
                if statuses.iter().any(|status| status.is_connected()) {
                    was_connected = true;
                    continue;
                }
                if was_connected || statuses.iter().any(|status| status.last_error().is_some()) {
                    return true;
                }
            }
        }
    }
}

/// Add iroh's default relay map to an already bound endpoint without replacing an existing
/// primary configuration that uses the same relay URL.
pub async fn install_iroh_fallback(endpoint: &Endpoint, existing_urls: &[iroh::RelayUrl]) {
    for relay in config::iroh_fallback_relay_mode()
        .relay_map()
        .relays::<Vec<_>>()
    {
        if should_insert_fallback_relay(existing_urls, &relay.url) {
            endpoint.insert_relay(relay.url.clone(), relay).await;
        }
    }
}

fn initial_primary_relay_failed(has_connected: bool, has_error: bool) -> bool {
    !has_connected && has_error
}

fn should_insert_fallback_relay(
    existing_urls: &[iroh::RelayUrl],
    candidate: &iroh::RelayUrl,
) -> bool {
    !existing_urls.contains(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connected_primary_does_not_fallback_for_a_separate_initial_error() {
        assert!(!initial_primary_relay_failed(true, true));
        assert!(initial_primary_relay_failed(false, true));
    }

    #[test]
    fn fallback_does_not_replace_an_existing_relay_url() {
        let existing = "https://relay.example.test"
            .parse::<iroh::RelayUrl>()
            .unwrap();
        let other = "https://other-relay.example.test"
            .parse::<iroh::RelayUrl>()
            .unwrap();

        assert!(!should_insert_fallback_relay(
            std::slice::from_ref(&existing),
            &existing
        ));
        assert!(should_insert_fallback_relay(&[existing], &other));
    }
}
