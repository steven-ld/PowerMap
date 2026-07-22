# Domain SNI Dispatcher Report

## Outcome

Enabled domain mappings now share one production `127.0.0.1:443` listener. The listener reads a bounded TLS ClientHello prefix, extracts and lowercases the hostname SNI without terminating TLS, selects the matching enabled mapping, and supplies every consumed byte unchanged as the `handle_tunnel` prefix.

## Lifecycle

- The first enabled mapping performs preflight, binds the shared listener, then writes its exact `127.0.0.1` hosts marker.
- Additional enabled mappings add only their own hosts marker and registry entry; they do not bind another listener.
- Disabling or deleting the final enabled mapping removes its marker and cancels the shared listener.
- A listener-bind failure writes no hosts marker. A hosts-write failure releases the dispatcher whenever the registry has no enabled mappings.
- The global lifecycle mutex serializes the shared listener and hosts transitions without retaining user-controlled per-domain lock keys.

## SNI Handling

- Prefix buffering is capped at 16 KiB and ClientHello reads time out after five seconds.
- TLS handshake records and fragmented ClientHello payloads are parsed structurally. The forwarded bytes are never parsed in-place or rewritten.
- Missing, malformed, oversized, invalid-domain, disabled, and unknown SNI values close the local connection before any tunnel is opened.
- Per-mapping connection limits and accounting continue to apply after dispatch.

## Hardening Preserved

- Domain mutations require a configured `web_token`.
- Domain mappings are capped by `min(max_mappings, 256)`, including persisted configuration validation.
- Hosts entries remain exact PowerMap-owned `127.0.0.1` markers.

## Verification

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets` (79 passed)

Focused coverage includes TLS SNI normalization and malformed rejection, real TCP prefix replay equality, two mappings sharing an injected `127.0.0.1:0` listener, final-disable listener teardown, host-write ordering on bind failure, token gating, and domain caps.
