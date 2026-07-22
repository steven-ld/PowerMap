# Domain Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a left-navigation Domain mappings page that preserves a configured HTTPS URL by transparently tunneling its domain to an expose-side HTTPS endpoint.

**Architecture:** Domain mappings are a separate `AConfig` collection, but reuse the current TCP `OpenRequest` path with the configured domain and remote port. The administrator-run access runtime owns exact hosts-file marker edits, loopback-port preparation, lifecycle, API state, diagnostics, and cleanup. The UI uses a dedicated page rather than extending port mappings.

**Tech Stack:** Rust 2024, Tokio, Axum, Serde/TOML, existing iroh TCP tunnel protocol, static HTML/CSS/JavaScript console.

## Global Constraints

- Enabling a domain mapping requires PowerMap itself to run with administrator authority; it never attempts elevation from the console.
- Domain mappings bind loopback only and create exact, PowerMap-marked hosts entries only.
- Preserve TLS byte-for-byte. Do not terminate TLS or issue certificates.
- Resolve and dial the domain from expose through the existing allowlist path.
- Existing `Mapping` behavior and APIs remain compatible.
- Initial implementation supports macOS and Linux hosts files. Unsupported platforms report a clear status without changing system state.

---

### Task 1: Define and validate persisted domain mappings

**Files:**
- Modify: `src/config.rs`
- Modify: `README.md`
- Modify: `README.en.md`
- Test: `src/config.rs` test module

**Interfaces:**
- Produces `config::DomainMapping { domain, remote_port, enabled }`.
- Adds `AConfig::domain_mappings: Vec<DomainMapping>` with `serde(default)`.
- Produces `DomainMapping::validate(&self) -> Result<(), String>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn domain_mapping_roundtrips_and_defaults_to_https() {
    let mapping = DomainMapping::new("ai-router.dl-aiot.com");
    assert_eq!(mapping.remote_port, 443);
    assert!(mapping.validate().is_ok());
}

#[test]
fn domain_mapping_rejects_wildcards_ips_and_invalid_labels() {
    for domain in ["*.example.com", "127.0.0.1", "-bad.example", "bad..example"] {
        assert!(DomainMapping::new(domain).validate().is_err());
    }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `cargo test config::tests::domain_mapping_ -- --nocapture`

Expected: compilation failure because `DomainMapping` is undefined.

- [ ] **Step 3: Add the smallest compatible model**

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainMapping {
    pub domain: String,
    #[serde(default = "default_https_port")]
    pub remote_port: u16,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_https_port() -> u16 { 443 }
```

Validate lowercase DNS labels, at least one dot, no wildcard, no IP literal, a maximum length of 253, and nonzero port. Add `#[serde(default)] pub domain_mappings: Vec<DomainMapping>` to `AConfig` and TOML round-trip coverage.

- [ ] **Step 4: Run configuration tests**

Run: `cargo test config::tests`

Expected: PASS, including legacy configs that omit `domain_mappings`.

- [ ] **Step 5: Document the format and commit**

```toml
[[access.domain_mappings]]
domain = "ai-router.dl-aiot.com"
remote_port = 443
enabled = true
```

```bash
git add src/config.rs README.md README.en.md
git commit -m "feat: add domain mapping configuration"
```

### Task 2: Implement managed hosts-file operations

**Files:**
- Create: `src/domain_hosts.rs`
- Modify: `src/lib.rs`
- Test: `src/domain_hosts.rs`

**Interfaces:**
- Produces `HostsStore::at(PathBuf)`.
- Produces `ensure_loopback(domain) -> Result<(), HostsError>` and `remove_loopback(domain) -> Result<(), HostsError>`.
- Uses exact marker `# PowerMap domain mapping: <domain>`.

- [ ] **Step 1: Write a file-backed failing test**

```rust
#[test]
fn ensure_and_remove_only_own_marked_entry() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "127.0.0.1 existing.local\n").unwrap();
    let store = HostsStore::at(file.path());
    store.ensure_loopback("ai-router.dl-aiot.com").unwrap();
    store.remove_loopback("ai-router.dl-aiot.com").unwrap();
    assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "127.0.0.1 existing.local\n");
}
```

- [ ] **Step 2: Verify failure**

Run: `cargo test domain_hosts::tests::ensure_and_remove_only_own_marked_entry`

Expected: compilation failure because the module is absent.

- [ ] **Step 3: Implement atomic marker-scoped edits**

Read the file, remove only an exact PowerMap marker line, append `127.0.0.1 <domain> # PowerMap domain mapping: <domain>`, write a sibling temporary file, and rename atomically. Use `/etc/hosts` on macOS/Linux. Never invoke `sudo`; surface `PermissionDenied` for the native authorization layer.

- [ ] **Step 4: Verify edge cases and commit**

Run: `cargo test domain_hosts::tests`

Expected: PASS for idempotent add, exact removal, unrelated same-domain lines, and malformed marked lines.

```bash
git add src/domain_hosts.rs src/lib.rs Cargo.toml
git commit -m "feat: manage marked hosts entries for domains"
```

### Task 3: Add domain lifecycle and REST APIs

**Files:**
- Modify: `src/access.rs`
- Modify: `src/config.rs`
- Test: `src/access.rs` integration tests

**Interfaces:**
- Produces `GET/POST /api/domain-mappings`, `PUT/DELETE /api/domain-mappings/{domain}`, and `POST /api/domain-mappings/{domain}/toggle`.
- Produces `DomainMappingHandle` with cancellation and connection accounting matching `MappingHandle`.
- Produces `DomainMappingStatus { domain, remote_port, enabled, hosts_managed, local_listener, last_error }`.

- [ ] **Step 1: Write a failing API test**

```rust
#[tokio::test]
async fn domain_mapping_api_rejects_invalid_domain_before_system_mutation() {
    let app = test_state("admin-token").await;
    let response = app
        .oneshot(authenticated_post("/api/domain-mappings", r#"{"domain":"*.bad"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
```

Inject a temporary `HostsStore` and listener factory in test state. Tests must never modify `/etc/hosts` or bind port 443.

- [ ] **Step 2: Verify failure**

Run: `cargo test access::integration_tests::domain_mapping_api_ -- --nocapture`

Expected: `404 Not Found` until routes exist.

- [ ] **Step 3: Implement activation transaction**

Validate the domain, require that the running process has administrator authority, preflight using existing `OpenRequest { host: domain, port: remote_port, kind: Tcp }`, create the marked hosts entry, bind loopback 443, then publish the handle. If a step fails, roll back only completed steps. Accepted TCP streams call existing `handle_tunnel` with the domain and port. Do not inspect TLS bytes.

- [ ] **Step 4: Implement disable, delete, and startup recovery**

Disable cancels the listener and removes its exact marked entry. Delete also removes persistence. Startup restores enabled records; a stale marked entry combined with a bind failure becomes an actionable disabled status.

- [ ] **Step 5: Run and commit**

Run: `cargo test access::integration_tests`

Expected: PASS and no regression to `/api/mappings`.

```bash
git add src/access.rs src/config.rs src/domain_hosts.rs
git commit -m "feat: tunnel HTTPS domains through access mappings"
```

### Task 5: Build the Domain mappings console page

**Files:**
- Modify: `src/web/index.html`
- Test: manual browser verification against `cargo run --bin powermap -- --config /tmp/powermap-domain.toml`

**Interfaces:**
- Consumes domain-mapping APIs from Task 3.
- Produces tab `#domains`, accessible CRUD controls, and page-specific primary action.

- [ ] **Step 1: Add the page shell**

Add a `域名映射` tab after `端口映射`, page-specific `新建域名映射` action, and empty state: `保持原始 HTTPS 域名，无需修改业务地址。` Reuse existing tab, button, dialog, status-badge, and responsive sidebar patterns.

- [ ] **Step 2: Add the create editor**

Default editor fields contain only `域名`. An explicit `高级设置` disclosure contains `远端 HTTPS 端口`, default 443. Show the authorization notice only after submit.

- [ ] **Step 3: Connect state and errors**

Implement `loadDomainMappings`, `createDomainMapping`, `toggleDomainMapping`, `deleteDomainMapping`, and `renderDomainMappings`. Display managed-hosts, resolved target, listener status, and exact backend error. Disable destructive actions while requests are in flight.

- [ ] **Step 4: Verify responsive UI and commit**

Create an invalid domain and confirm validation feedback; run without administrator authority and confirm the prerequisite message. Inspect desktop plus a 390px viewport.

```bash
git add src/web/index.html
git commit -m "feat: add domain mappings console page"
```

### Task 6: Final documentation and release checks

**Files:**
- Modify: `README.md`
- Modify: `README.en.md`
- Modify: `CHANGELOG.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Document user prerequisites**

Document preserve-URL behavior, expose-side DNS, default remote port 443, runtime administrator authorization, exact hosts rollback, port conflict handling, and upstream-certificate requirement.

- [ ] **Step 2: Add CI compilation coverage**

Keep `cargo test --all-targets` as the behavior gate and add platform-specific helper compilation checks that never request elevation.

- [ ] **Step 3: Run full verification**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release --bin powermap
sh -n scripts/install.sh
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 4: Commit**

```bash
git add README.md README.en.md CHANGELOG.md .github/workflows/ci.yml
git commit -m "docs: document domain mappings"
```
