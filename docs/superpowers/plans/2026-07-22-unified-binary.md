# Unified Binary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the public server/client binaries with one `powermap` binary that automatically migrates existing configuration.

**Architecture:** Add a `Config` wrapper with optional `ExposeConfig` and `AccessConfig` sections, plus an atomic migration loader. The existing `expose::run` and `access::run` modules remain the role implementations; a new binary loads the wrapper and starts one or both roles with a shared cancellation token.

**Tech Stack:** Rust 2024, Tokio, Clap, Serde/TOML, iroh, Axum.

## Global Constraints

- Keep the wire protocol and credential JSON format unchanged.
- Preserve forward allowlist empty = allow-all and reverse allowlist empty = deny-all.
- Write and validate `powermap.toml` before deleting any legacy configuration.
- Do not publish or install `powermap-server` or `powermap-client` after this change.

---

### Task 1: Unified Configuration and Migration

**Files:**
- Modify: `src/config.rs`
- Test: `src/config.rs`

**Interfaces:**
- Produces `Config { expose: Option<BConfig>, access: Option<AConfig> }`.
- Produces `load_unified(path: &Path, legacy_role: Option<Role>) -> Result<Config>`.

- [ ] Write tests for new-format round trip, server-only migration, client-only migration, combined migration, and a malformed legacy file preserving its source.
- [ ] Run `cargo test config::tests::unified -q` and confirm the missing loader causes failure.
- [ ] Add the wrapper config, validation, old-format detection, atomic save, and only-then deletion.
- [ ] Run `cargo test config::tests::unified -q` and confirm every migration test passes.

### Task 2: Unified CLI Lifecycle

**Files:**
- Create: `src/bin/powermap.rs`
- Modify: `Cargo.toml`, `src/config.rs`
- Test: `src/config.rs`

**Interfaces:**
- Consumes `config::load_unified` and `access::run` / `expose::run`.
- Produces a `powermap` executable with default, `access`, and `expose` modes.

- [ ] Add a failing config test that role selection rejects a requested absent role.
- [ ] Run that single test and observe the expected failure.
- [ ] Add the CLI entry point, shared cancellation watcher, concurrent role startup, and error propagation.
- [ ] Run `cargo test config::tests::unified -q` and `cargo check --bin powermap`.

### Task 3: Remove Legacy Distribution Surface

**Files:**
- Modify: `Cargo.toml`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/install.sh`, `scripts/install.ps1`, `deployment/README.md`
- Delete: `src/bin/client.rs`, `src/bin/server.rs`, `deployment/systemd/powermap-client.service`, `deployment/systemd/powermap-server.service`, `deployment/launchd/com.powermap.client.plist`, `deployment/launchd/com.powermap.server.plist`, `deployment/windows/register-scheduled-task.ps1`

- [ ] Update release and installation assertions to require only `powermap`.
- [ ] Update deployment guidance to invoke `powermap --config /etc/powermap/powermap.toml`.
- [ ] Run `cargo check --all-targets` and inspect `cargo metadata` to confirm exactly one binary target.

### Task 4: Documentation and Full Verification

**Files:**
- Modify: `README.md`, `README.en.md`, `CHANGELOG.md`, `.gitignore`

- [ ] Replace server/client setup instructions with expose/access configuration and automatic migration behavior.
- [ ] Document that migration deletes the old configuration only after the new file is successfully written.
- [ ] Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, and `cargo build --release`.
