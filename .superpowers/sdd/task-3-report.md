# Task 3 Report: PeerManager and Isolated Access Runtimes

## Delivered

- Replaced the access-wide runtime link with `PeerManager`, keyed by immutable peer IDs.
- Each lazily-created peer link owns an independent Iroh endpoint, relay runtime, credential lock, connection cache, and fallback watchdog.
- Enabled port and domain mappings acquire/release the owning peer runtime. A peer runtime is cancelled and dropped when its final enabled mapping stops.
- Mapping start and persistence normalize blank legacy ownership to the runtime's sole `默认对端` ID, without consulting disk as the runtime authority. Unknown owners are rejected before allocating a listener or endpoint.
- Domain SNI dispatch resolves the selected mapping's peer immediately before opening its tunnel.
- Startup derives the persistent expose public key and rejects a peer pointing at that exact local identity; NAT hairpin paths remain unaffected.
- Legacy single-peer adapters remain available only for the one migrated default peer.

## TDD Evidence

1. Extended `create_and_list_preserve_the_optional_mapping_name` to require the returned and persisted `peer_id` to be `default`.
2. Before the fix, `cargo test create_and_list_preserve_the_optional_mapping_name -- --nocapture` failed because legacy creation took no ID from the absent on-disk config, then persistence rejected the blank owner.
3. Implemented runtime default-ID resolution and normalization before mapping lifecycle and snapshot persistence.
4. Reran the regression successfully: 1 passed, 0 failed.
5. Added isolated-runtime coverage for distinct/lazy links, peer update isolation, inactive links, view/removal behavior, unknown owners, owner-change listener rebuild, and self-peer rejection.

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo test access::integration_tests -- --nocapture`: 77 passed, 0 failed.
- `cargo test`: 174 passed, 0 failed; doc tests: 0 passed, 0 failed.
- `git diff --check`: passed.
- Normal compilation/test output has no Task 3 dead-code warnings.

## Files Changed

- `src/access.rs`
- `src/bin/powermap.rs`
- `src/expose.rs`

## Self-Review

- All lifecycle entry points resolve immutable mapping ownership from `PeerManager`; persistence repeats that normalization for pre-existing legacy handles.
- Per-peer link state is not shared across IDs; changing peer A's relay/credentials cannot invalidate peer B's link.
- Disabled mappings validate/normalize their owner without creating a link, and enabled unknown owners fail before allocation.
- The local expose-key check compares persistent public keys only and does not attempt generic cycle or NAT hairpin detection.

## Concerns

- `cargo clippy --all-targets -- -D warnings` remains non-clean only because of a pre-existing style suggestion in `src/tunnel.rs`. It does not affect the passing test suite or introduce dead-code warnings.

## Review Fixes

- Read-only status, diagnostics, onboarding, credential, relay, and relay-probe paths now use a cached link or a peer configuration snapshot, so they never create an Endpoint for an inactive peer.
- Port and domain preflight temporarily acquire a peer runtime and release it on every result path. This preserves remote preflight behavior without retaining a hot connection.
- Link creation and active-reference acquisition now happen while holding the same runtime lock. A final release therefore cannot cancel a link between creation and reference registration.
- The port-mapping publish race now drains the unpublished handle before returning a conflict or mapping-limit error, releasing its peer reference and watchdog.

## Review-Fix Verification

- RED: `status_does_not_activate_an_inactive_default_peer` and `mapping_preflight_releases_an_inactive_default_peer` each failed with `link_count == 1` before the read-only/temporary-lease changes.
- GREEN: both focused lifecycle regressions passed after the change.
- `cargo test http_route_targets_are_preflighted_on_create_and_update -- --nocapture`: passed after aligning the loopback fixture with active-reference semantics.
- `cargo fmt --all`: passed.
- `cargo test access::integration_tests -- --nocapture`: 79 passed, 0 failed.
