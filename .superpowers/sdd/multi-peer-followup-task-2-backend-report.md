# Multi-Peer Follow-Up Task 2: Backend Report

## Scope

Implemented the backend half of Task 2 in `src/access.rs` only, plus this
report. The independently modified `src/web/index.html`, configuration code,
dependencies, and unrelated untracked documentation were not changed.

`GET /api/credential` and `GET /api/relay` now return the existing legacy
default-peer ambiguity message as `409 Conflict` when the peer configuration
is not exactly one peer named the legacy default. The successful response path
for exactly one legacy default peer is unchanged.

## TDD Evidence

RED test added first: `legacy_global_reads_reject_multi_peer_configuration`.
It replaces the test default peer with exactly two named peers, requests both
legacy global endpoints, and asserts `409 Conflict` plus the existing
ambiguity response body.

RED command:

```text
PATH='/Users/ga666666/.rustup/toolchains/1.91.0-aarch64-apple-darwin/bin:'"$PATH" cargo test legacy_global_reads_reject_multi_peer_configuration -- --nocapture
```

RED result: failed as intended. `GET /api/credential` returned `200 OK`
instead of the expected `409 Conflict`; prior behavior fabricated an empty
credential payload when no unique legacy default peer could be selected.

Implementation: changed both GET handlers to return
`Result<Json<_>, (StatusCode, String)>` and map the existing
`legacy_default_peer_config` ambiguity error to `StatusCode::CONFLICT`.

GREEN command:

```text
PATH='/Users/ga666666/.rustup/toolchains/1.91.0-aarch64-apple-darwin/bin:'"$PATH" cargo test legacy_global_reads_reject_multi_peer_configuration -- --nocapture
```

GREEN result: passed, 1 passed and 0 failed. The test verifies both
`/api/credential` and `/api/relay`.

## Verification

```text
PATH='/Users/ga666666/.rustup/toolchains/1.91.0-aarch64-apple-darwin/bin:'"$PATH" cargo fmt
PATH='/Users/ga666666/.rustup/toolchains/1.91.0-aarch64-apple-darwin/bin:'"$PATH" cargo test access::integration_tests -- --nocapture
git diff --check
```

Results:

- `cargo fmt` completed successfully.
- Access integration suite: 94 passed, 0 failed.
- `git diff --check` completed with no output.

## Files Changed

- `src/access.rs`: regression coverage and explicit conflict responses for
  legacy global credential and relay reads.
- `.superpowers/sdd/multi-peer-followup-task-2-backend-report.md`: this
  backend implementation record.

## Concerns

None for the backend contract. This change deliberately affects only GET
legacy-global reads in multi-peer configurations; peer-specific APIs remain
the source of configuration state, and all exactly-one-default-peer GET
semantics remain covered by the passing integration suite.
