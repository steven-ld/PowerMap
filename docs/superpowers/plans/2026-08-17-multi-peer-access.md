# Multi-Peer Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow an access node to maintain multiple named peers with independent Iroh endpoints
and relay settings, while making every port and domain mapping explicitly belong to one peer.

**Architecture:** `config::PeerConfig` becomes the persistent access-side connection unit and a
`PeerManager` owns the lazy, per-peer `Link` runtimes. Mapping handlers resolve immutable peer IDs
through that manager; the web console submits IDs while displaying required unique names. The
expose endpoint remains independent and the old root relay configuration is kept only for it.

**Tech Stack:** Rust 2024, Tokio, Axum 0.8, Iroh 1, Serde/TOML, vanilla HTML/CSS/JavaScript.

## Global Constraints

- Retain read compatibility with v0.9.0 single-credential configuration and backups.
- Migrate an old credential or mapping into one peer named `默认对端`; map all existing port and
  domain mappings to its immutable ID.
- A peer name is trimmed, nonempty, at most 60 characters, and unique within one access config.
- A mapping stores `peer_id`; a peer rename never changes mapping ownership, and deleting a peer
  with referenced mappings must return `409 Conflict` without auto-rebinding anything.
- Every access peer owns its relay settings, endpoint, connection pool, watchdog, and path state.
  A peer without enabled mappings must not keep an endpoint or hot connection alive.
- Keep the expose endpoint's relay settings independent. Never change another peer when a
  credential or relay configuration is edited.
- Reject a peer matching the local persistent expose identity. Treat loopback-resolved targets as
  an explicit risk: preflight reports it and mapping save requires acknowledgement.
- Do not claim generic TCP can identify arbitrary multi-machine cycles. NAT hairpin paths remain
  valid direct or relay paths, not loop rejections.
- Preserve atomic persistence and secret redaction. Do not add dependencies.

---

### Task 1: Persistent Peer Model and v0.9.0 Migration

**Files:**
- Modify: `src/config.rs:75-410, 605-950, 1201-1600`
- Test: `src/config.rs:1201-1600`

**Interfaces:**
- Produces `config::PeerConfig { id, name, node_id, token, published_targets, relay }`.
- Produces `AConfig::peer(&self, id: &str) -> Option<&PeerConfig>` and
  `AConfig::legacy_default_peer_id(&self) -> Option<&str>`.
- Extends `Mapping` and `DomainMapping` with `peer_id: String` and
  `allow_loopback_target: bool`.
- Produces `Config::normalize_access_peers() -> Result<bool, String>`; `true` means the caller
  must persist the migrated representation after a successful load/save cycle.

- [ ] **Step 1: Write failing configuration tests**

Add tests covering a v0.9.0 TOML payload with top-level access credential, relay, one port
mapping, and one domain mapping. Assert normalization creates exactly one peer named `默认对端`,
copies credential/relay/published targets, assigns both mapping IDs, and serializes no legacy
credential fields. Add independent tests that reject duplicate trimmed names, missing mapping
peer IDs, references to unknown peers, and `allow_loopback_target` without a peer.

```rust
#[test]
fn legacy_access_migrates_to_one_named_peer() {
    let mut config: Config = toml::from_str(LEGACY_ACCESS_TOML).unwrap();
    assert!(config.normalize_access_peers().unwrap());
    let access = config.access.as_ref().unwrap();
    assert_eq!(access.peers.len(), 1);
    assert_eq!(access.peers[0].name, "默认对端");
    assert!(access.mappings.iter().all(|m| m.peer_id == access.peers[0].id));
    assert!(access.domain_mappings.iter().all(|m| m.peer_id == access.peers[0].id));
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cargo test config::tests::legacy_access_migrates_to_one_named_peer`

Expected: FAIL because `PeerConfig`, `normalize_access_peers`, and mapping ownership do not yet
exist.

- [ ] **Step 3: Add the peer and mapping schema**

Add the persistent structure and validation. Keep legacy fields deserializable but mark them
`skip_serializing`; only `peers` is emitted for new access configuration. Generate an opaque
locally unique ID with the existing timestamp/counter pattern; this ID is not a credential.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub id: String,
    pub name: String,
    #[serde(default)] pub node_id: String,
    #[serde(default)] pub token: String,
    #[serde(default)] pub published_targets: Vec<PublishedTarget>,
    #[serde(default)] pub relay: RelaySettings,
}

impl PeerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() { return Err("peer id cannot be empty".into()); }
        if self.name.trim().is_empty() || self.name.chars().count() > 60 {
            return Err("peer name must contain 1-60 characters".into());
        }
        if self.node_id.trim().is_empty() != self.token.trim().is_empty() {
            return Err("peer node_id and token must both be set or both be empty".into());
        }
        self.relay.validate()
    }
}
```

Make `AConfig::validate` validate unique IDs, unique trimmed names, each peer, and each mapping's
peer reference. Redact each peer token and relay bearer when exporting. Update `load_config` and
`save_access` to call normalization before validation and to preserve the root relay only for the
expose endpoint.

- [ ] **Step 4: Add migration and round-trip coverage**

Cover empty legacy access configs, legacy configs that contain mappings but no credential,
new-format peer round trips, redacted exports, and rejection of stale peer references. Keep all
existing config tests compiling by adding the required fields to their struct literals.

- [ ] **Step 5: Run the configuration test module**

Run: `cargo test config::tests`

Expected: PASS, including old configuration tests and the new migration/validation cases.

- [ ] **Step 6: Commit the persistent model**

```bash
git add src/config.rs
git commit -m "feat: add persistent access peers"
```

### Task 2: Loopback-Aware Preflight Protocol

**Files:**
- Modify: `src/proto.rs:31-145`
- Modify: `src/tunnel.rs:520-700`
- Modify: `src/access.rs:810-850, 3981-4095`
- Test: `src/proto.rs`, `src/tunnel.rs`, and `src/access.rs` test modules

**Interfaces:**
- Extends `proto::OpenRequest` with defaulted `preflight: bool` and `allow_loopback_target: bool`.
- Produces `proto::OpenStatus::{Ok, Error(String), LoopRisk(String)}` from `read_status`.
- Produces `access::PreflightResult { ready, loop_risk, checks }`, where `loop_risk` is an
  optional structured warning.
- Consumes `Mapping::allow_loopback_target` and `DomainMapping::allow_loopback_target`.

- [ ] **Step 1: Write failing protocol and preflight tests**

Test that an old JSON request still deserializes, a preflight request reaching an expose-side
loopback address returns `OpenStatus::LoopRisk`, and a normal request without
`allow_loopback_target` is rejected before it dials the target. Test that the acknowledgement
flag permits the same resolved loopback target.

```rust
#[tokio::test]
async fn loopback_target_requires_explicit_acknowledgement() {
    let request = OpenRequest { host: "127.0.0.1".into(), preflight: true, ..test_request() };
    assert!(matches!(serve_preflight(request).await, OpenStatus::LoopRisk(_)));
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cargo test loopback_target_requires_explicit_acknowledgement`

Expected: FAIL because the request and response types do not carry loopback state.

- [ ] **Step 3: Extend the wire response without breaking old requests**

Reserve a status value distinct from `STATUS_OK` and `STATUS_ERR`; encode it with the existing
error-message framing so old clients fail closed. Make `read_status` return an enum, then update
`open_tunnel` to turn `LoopRisk` into a typed error for regular tunnel creation while mapping
preflight reads the status directly.

```rust
pub enum OpenStatus { Ok, Error(String), LoopRisk(String) }
pub const STATUS_LOOP_RISK: u8 = 2;
```

- [ ] **Step 4: Enforce loopback policy on the expose side**

After `TargetPolicy::resolve_allowed`, detect `SocketAddr::ip().is_loopback()`. For preflight,
return `LoopRisk` unless acknowledged. For normal streams, refuse an unacknowledged loopback
target before `serve_tcp` or `serve_udp` opens a socket. Preserve all allowlist checks and audit
events.

- [ ] **Step 5: Thread acknowledgement through both mapping types**

Make port preflight return the warning in JSON. Make port creation/update repeat the preflight
route check and reject a warning unless the request explicitly acknowledges it; persist the result
in `allow_loopback_target`. Apply the same validation to domain mapping create/update before hosts
or listener mutations.

- [ ] **Step 6: Run focused protocol and tunnel tests**

Run: `cargo test proto::tests`

Expected: PASS.

Run: `cargo test tunnel::tests`

Expected: PASS.

- [ ] **Step 7: Commit the loopback protocol**

```bash
git add src/proto.rs src/tunnel.rs src/access.rs
git commit -m "feat: require acknowledgement for loopback targets"
```

### Task 3: PeerManager and Isolated Access Runtimes

**Files:**
- Modify: `src/access.rs:50-350, 768-850, 4181-4515, 5567-5810`
- Modify: `src/bin/powermap.rs:50-80`
- Modify: `src/expose.rs:25-55` only if a public helper is needed to derive the local expose ID
- Test: `src/access.rs:1208-3150`

**Interfaces:**
- Produces `PeerManager` with `get_link(peer_id)`, `peer_views()`, `upsert_peer`, and
  `remove_peer` methods.
- Produces lazy `PeerLink` construction from `config::PeerConfig`; each active peer has a distinct
  `Endpoint`, `RelayRuntime`, credential lock, cached connection, and watchdog.
- Changes `access::run` to accept `AConfig`, config path, cancellation token, and an optional
  local expose public key. The binary passes the key derived from the configured expose identity.

- [ ] **Step 1: Write failing isolated-runtime tests**

Extend `test_state` with two valid peer configurations. Assert different IDs return different
links/endpoints; updating peer A's relay or credential does not invalidate peer B; an inactive
peer does not allocate a link; and editing a mapping's `peer_id` rebuilds its listener handle
instead of retaining the old captured link.

```rust
#[tokio::test]
async fn changing_one_peer_does_not_invalidate_another_peer() {
    let state = test_state_with_peers([peer("a"), peer("b")]).await;
    let b = state.peers.get_link("b").await.unwrap();
    state.peers.update_relay("a", forced_relay()).await.unwrap();
    assert!(b.can_open_new_connections().await);
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cargo test changing_one_peer_does_not_invalidate_another_peer`

Expected: FAIL because `AppState` has only one `link`.

- [ ] **Step 3: Replace the global access Link with PeerManager**

Move the current `Link` and `RelayRuntime` logic behind a manager keyed by peer ID. Construct an
Endpoint only from the selected `PeerConfig.relay`; start its fallback monitor when it is created.
Drop and shut down the runtime when no enabled port or domain mapping references it. Keep each
peer's existing retry/backoff behavior.

```rust
struct PeerManager {
    peers: Arc<RwLock<HashMap<String, config::PeerConfig>>>,
    links: Arc<Mutex<HashMap<String, Link>>>,
    local_expose_id: Option<PublicKey>,
    cancel: CancellationToken,
}
```

- [ ] **Step 4: Route mapping lifecycle through the owning peer**

In `start_mapping_owned`, reject an unknown peer ID and capture only its returned `Link`. When
an update changes `peer_id`, rebuild the handle even if local address and enabled state are
unchanged. In the shared domain listener, resolve the SNI mapping's peer link immediately before
opening the stream. Reference-count enabled mappings and stop a peer runtime when its count falls
to zero.

- [ ] **Step 5: Add deterministic self-peer rejection**

Derive the local persistent expose public key once at startup when expose is configured. Reject
peer creation/loading if its parsed `node_id` matches this key; include an actionable error, but
do not classify ordinary NAT hairpin paths as self-connections.

- [ ] **Step 6: Run the access runtime test module**

Run: `cargo test access::tests`

Expected: PASS, including mapping lifecycle and independent peer runtime tests.

- [ ] **Step 7: Commit the runtime isolation**

```bash
git add src/access.rs src/bin/powermap.rs src/expose.rs
git commit -m "feat: isolate access connections by peer"
```

### Task 4: Peer and Mapping HTTP APIs

**Files:**
- Modify: `src/access.rs:1002-1180, 3950-5370, 4763-4804`
- Test: `src/access.rs:1208-3150`

**Interfaces:**
- Produces `GET/POST /api/peers` and `PUT/DELETE /api/peers/{id}`.
- Extends mapping/domain create and update bodies with `peer_id` and
  `acknowledge_loop_risk`.
- Produces peer-aware list, stats, health, event, export, and import responses.

- [ ] **Step 1: Write failing Axum handler tests**

Add tests that create two named peers, reject a duplicate name, update one peer without changing
the other, reject deletion of a referenced peer with `409` plus mapping identifiers, and allow
deletion after explicit mapping removal. Add mapping tests for required `peer_id`, exact peer
selection, safe legacy omission only with the single migrated default peer, and rejection when
two peers exist. Repeat the ownership checks for domain mapping endpoints.

```rust
#[tokio::test]
async fn deleting_referenced_peer_returns_conflict_with_mapping_list() {
    let app = app(state_with_peer_and_mapping().await);
    let response = app.oneshot(Request::delete("/api/peers/peer-a").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response_json(response).await["mappings"][0], "127.0.0.1:6379");
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cargo test deleting_referenced_peer_returns_conflict_with_mapping_list`

Expected: FAIL because peer routes and ownership checks do not exist.

- [ ] **Step 3: Implement peer CRUD transactionally**

Add peer request/view types that never redact values required for a local editor response but
never put tokens in events or diagnostics. Validate all candidate configs before mutating the
manager, persist through `persist_config`, and restore the previous peer if saving fails. On
delete, enumerate both mapping collections first and return `409` without changing state if any
reference exists.

- [ ] **Step 4: Make every mapping API peer-aware**

Require and validate `peer_id` in port/domain bodies, list responses, stats, health summaries,
and preflight. Resolve `peer_name` only for display. Preserve old `GET/POST /api/credential` as a
single-default-peer compatibility adapter; do not expose it as the multi-peer UI path. Replace
global access relay writes with peer-specific relay edits.

- [ ] **Step 5: Update transfer and diagnostic behavior**

Export/import the complete peer collection. Redact every peer credential and relay token unless
credentials are explicitly requested. Import must validate all peer IDs/names and every mapping
reference before starting/replacing listeners, then rollback manager state if persistence fails.

- [ ] **Step 6: Run the API test module**

Run: `cargo test access::tests`

Expected: PASS, including existing API tests and peer CRUD/mapping ownership coverage.

- [ ] **Step 7: Commit the API layer**

```bash
git add src/access.rs
git commit -m "feat: add peer-aware access APIs"
```

### Task 5: Peer-Aware Management Console

**Files:**
- Modify: `src/web/index.html:250-850, 950-1280, 1479-3050, 3235-3450`
- Test: browser smoke test against a local `powermap` process after Task 4

**Interfaces:**
- Consumes `/api/peers` and peer-aware mapping/domain responses from Task 4.
- Submits `{ peer_id, acknowledge_loop_risk }` for mapping preflight/create/update.
- Produces a peer list/editor and mandatory peer selectors for port/domain mappings.

- [ ] **Step 1: Add peer-console behavior tests or a repeatable browser smoke script**

Create a local configuration with two peers and use the existing browser test tooling to verify:
the Peers page shows both names; mapping forms cannot submit without a peer selection; selecting a
peer sends its ID; a mapping row shows its peer name; and deleting a referenced peer shows the
server conflict message. Save screenshots for desktop and mobile widths.

- [ ] **Step 2: Run the smoke test to verify it fails**

Run: `cargo run -- --config /tmp/powermap-multi-peer-ui.toml`

Expected: the current console exposes one global connection form and no peer selector.

- [ ] **Step 3: Replace access-wide connection controls with peer management**

Rename the connection tab to Peers. Render a compact list with name, state, path, active relay,
and mapping count. Use a focused add/edit surface that requires the name and keeps relay controls
within the selected peer. Remove the access-wide relay editor path; do not remove expose-side
configuration support from the backend.

- [ ] **Step 4: Add mandatory selectors and loop-risk confirmation**

Add a peer-name `<select>` to both port and domain forms. Keep selected IDs in form state, refresh
published target suggestions when the selected peer changes, and render peer name in each table
row. If preflight returns `loop_risk`, show its risk copy and require the existing confirmation
modal before a second acknowledged save request.

- [ ] **Step 5: Run browser validation and responsive checks**

Run the new smoke script at 1440x900 and 390x844. Verify no label, selector, table value, or
modal text overflows or overlaps, and that every submit path carries a peer ID.

- [ ] **Step 6: Commit the console changes**

```bash
git add src/web/index.html
git commit -m "feat: manage mappings by named peer"
```

### Task 6: Documentation, Release Notes, and Full Verification

**Files:**
- Modify: `README.md:120-280, 360-470`
- Modify: `README.en.md` corresponding setup/configuration sections
- Modify: `CHANGELOG.md`
- Modify: `docs/releases/` with a new multi-peer release note if the repository release format
  requires one

**Interfaces:**
- Documents the `access.peers` schema, migration to `默认对端`, per-peer relay ownership, mapping
  peer selection, loop-risk acknowledgement, and NAT hairpin boundary.

- [ ] **Step 1: Update user documentation with executable configuration examples**

Show two named peers, each with its own relay settings, and two mappings that use the resulting
peer IDs. Explain that renaming is safe, deletion requires explicit mapping migration/removal, and
generic multi-machine TCP loops cannot be inferred automatically.

- [ ] **Step 2: Add a changelog entry**

Describe multi-peer access, mandatory mapping ownership, independent relay settings, v0.9.0
migration, and loopback warnings without exposing any tokens or operational credentials.

- [ ] **Step 3: Run formatting, unit, lint, and build verification**

Run: `cargo fmt --check`

Expected: PASS.

Run: `cargo test`

Expected: PASS.

Run: `cargo clippy --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo build --release`

Expected: PASS.

- [ ] **Step 4: Commit documentation and verification changes**

```bash
git add README.md README.en.md CHANGELOG.md docs
git commit -m "docs: explain multi-peer access"
```

## Plan Self-Review

- Spec coverage: Tasks 1-4 implement named peers, migration, independent endpoints/relays,
  peer-owned port/domain mappings, delete protection, import/export, self-peer rejection, and
  acknowledged loopback risk. Task 5 implements the required user-facing selection and status.
  Task 6 documents the migration and executes all required verification.
- Placeholder scan: no task relies on unspecified behavior; each behavior names its owning types,
  functions, endpoints, files, and test command.
- Type consistency: `PeerConfig`, `peer_id`, `allow_loopback_target`, `PeerManager`, and
  `OpenStatus` are introduced before later tasks consume them.
