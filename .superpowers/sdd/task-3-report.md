# Task 3 Report: Domain Lifecycle and REST APIs

## Delivered

- Added separate `GET/POST /api/domain-mappings`, `PUT/DELETE /api/domain-mappings/{domain}`, and `POST /api/domain-mappings/{domain}/toggle` APIs.
- Added `DomainMappingHandle` and `DomainMappingStatus` with cancellation, connection accounting, managed-hosts state, listener state, and actionable errors.
- Activation is transactional: validation, current-process administrator check, expose-side TCP `OpenRequest` preflight, exact hosts marker, then loopback listener. A failed listener bind rolls back the exact marker.
- The process never attempts elevation. macOS/Linux use `geteuid()` directly with no shell; unsupported platforms return HTTP 501 from domain operations.
- Injected test hosts file, ephemeral listener factory, and administrator check. Tests do not touch `/etc/hosts` or bind port 443.
- Disable/delete cancel the listener and remove only the exact PowerMap marker. Startup restores enabled records and retains failed records as disabled with an error.

## TDD Evidence

1. Added `domain_mapping_api_rejects_invalid_domain_before_system_mutation`.
2. Ran `cargo test access::integration_tests::domain_mapping_api_ -- --nocapture` before routes existed; it failed as intended with `404 Not Found` instead of the expected `400 Bad Request`.
3. Implemented the route and lifecycle, then reran the focused test; it passed.
4. Added coverage for disabled-record creation without system mutation and administrator-denied enablement.

## Verification

- `cargo fmt --all`
- `cargo test access::integration_tests -- --nocapture` (23 passed)
- `cargo test config::tests -- --nocapture` (24 passed)
- `cargo test domain_hosts::tests -- --nocapture` (5 passed)
- `git diff --check`

The attempted combined command `cargo test config::tests domain_hosts::tests -- --nocapture` was rejected by Cargo because it accepts one test filter; both filters were then run separately and passed.

## Review Follow-up

- `failed_disable_cleanup_preserves_retryable_hosts_error_state` proves a failed disable keeps a disabled mapping with `hosts_managed = true` and an actionable error in both the response and persisted runtime configuration. A restarted runtime detects the retained exact marker and keeps the cleanup state visible for a later disable/delete retry.
- `concurrent_create_does_not_rollback_the_published_mapping_hosts_marker` holds the first injected listener activation while a second create competes for the same domain. The per-domain operation lock admits only the first activation; the second returns conflict without invoking its simulated bind failure or removing the successful mapping's marker.
- Follow-up verification: both focused regressions pass, and `cargo test --all-targets` passes with 71 tests.
