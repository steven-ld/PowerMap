# PowerMap

<div align="center">

<img src="assets/powermap-logo.svg" alt="PowerMap" width="420" />

![PowerMap](https://img.shields.io/badge/PowerMap-P2P%20Tunnel-3370ff?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-green?style=for-the-badge)
![Rust](https://img.shields.io/badge/Rust-1.85+-orange?style=for-the-badge&logo=rust&logoColor=white)
![iroh](https://img.shields.io/badge/Built%20on-iroh-black?style=for-the-badge)

A NAT-traversal tunnel built on [iroh](https://iroh.computer) (P2P / QUIC). Two machines hole-punch a direct link (or fall back to relay) to **expose services on an intranet device to your home computer** — no public IP, no VPN, no router config.

[![CI](https://github.com/steven-ld/PowerMap/actions/workflows/ci.yml/badge.svg)](https://github.com/steven-ld/PowerMap/actions/workflows/ci.yml)
[![Release](https://github.com/steven-ld/PowerMap/actions/workflows/release.yml/badge.svg)](https://github.com/steven-ld/PowerMap/actions/workflows/release.yml)

**🔗 Website: [powermap.ga666666.com](https://powermap.ga666666.com)**

[简体中文](README.md) • **English**

</div>

---

## 💡 Design Philosophy

Remote access to an intranet service typically requires a public IP, a VPN, or router port forwarding — each carrying cost, exposure, or changes to network infrastructure. PowerMap establishes an end-to-end encrypted tunnel between the two sides via iroh's P2P hole punching, requiring none of them. The design follows four principles.

### 1. Zero Inbound Exposure

The tunnel server listens on no inbound port; it only dials out to the iroh relay network, leaving no scannable attack surface. It operates correctly behind firewalls, NAT, and even carrier-grade NAT.

### 2. End-to-End Encryption

The entire link is encrypted with QUIC + rustls, and the access credential is the only entry point. Relay nodes forward ciphertext alone and cannot inspect tunnel contents.

### 3. Out of the Box

No database, no central server, no account system. The tunnel server generates a credential on first run; the client pastes it and establishes mappings through the web admin UI.

### 4. Production-Grade Control

Target allowlists (CIDR + port), per-tenant tokens, audit logging, resource caps, and graceful shutdown — built for sustained operation rather than a one-off demo.

---

## ✨ Features

- **P2P Direct Connect** — iroh hole-punches automatically; direct on most networks, auto-fallback to relay otherwise
- **Zero Inbound Ports** — the intranet side exposes no listening port, no attack surface
- **Web Admin UI** — two-page interface: port mappings + connection management, live traffic metrics
- **End-to-End Encryption** — QUIC + rustls throughout; relays never see plaintext
- **Target Allowlist** — CIDR network + port double restriction, DNS-rebinding (TOCTOU) safe
- **Multi-Tenant** — per-client token / allowlist / concurrency cap, rotate or revoke individually
- **Audit Logging** — one JSON line per dial (allowed/denied/timeout/failed)
- **Virtual-IP Mapping** — map multiple intranet devices to different local loopback addresses
- **Prometheus Metrics** — `/metrics` endpoint covering tunnels / traffic / reconnects
- **Auto Reconnect** — background watchdog + exponential backoff, detects drops within ~15s
- **Credential Persistence** — connect once, auto-restore on restart
- **HTTPS Admin UI** — optional TLS reusing iroh's ring backend, no extra C deps
- **Cross-Platform** — prebuilt binaries for Linux / macOS / Windows
- **Docker Ready** — the intranet side fits container deployment perfectly

---

## 🖥️ Screenshots

Flat dual-theme web admin UI with a two-page layout, showing live connection status and transport path (P2P direct / relayed) in real time.

| Port Mappings (home) | Connection Settings |
|---|---|
| ![Port Mappings](assets/screenshots/light-mappings.png) | ![Connection Settings](assets/screenshots/light-connection.png) |

---

## 🏗️ Architecture

```mermaid
flowchart LR
    subgraph intranet["Intranet side (office / dorm / on-site)"]
        B["powermap-server (server B)<br/>exposes ALPN service · no inbound port"]
        SVC["intranet service<br/>192.168.1.101:6379 etc."]
        B -->|intranet dial| SVC
    end

    subgraph home["Home side"]
        A["powermap-client (client A)<br/>Web admin UI :8088"]
        LOCAL["local port<br/>127.0.0.1:6379"]
        A -->|listen| LOCAL
    end

    USER(["you / redis-cli etc."]) -->|connect local port| LOCAL
    A <-->|"iroh P2P punch / relay<br/>QUIC + rustls end-to-end encryption"| B

    style B fill:#3370ff,stroke:#2451b8,color:#fff
    style A fill:#3370ff,stroke:#2451b8,color:#fff
    style SVC fill:#e8f0ff,stroke:#3370ff,color:#1a1a1a
    style LOCAL fill:#e8f0ff,stroke:#3370ff,color:#1a1a1a
    style USER fill:#f0f0f0,stroke:#999,color:#1a1a1a
```

| Side | Runs on | Role |
|---|---|---|
| **powermap-server** (server **B**) | An intranet device | Exposes one ALPN service via iroh, generates a credential; dials intranet targets on client request and relays bidirectionally |
| **powermap-client** (client **A**) | Your home computer | Takes the credential, serves the web admin UI, maps local ports to intranet targets |

Install **B** on an intranet device and your home **A** can reach **any device on that intranet** — e.g. map intranet `192.168.1.101:6379` to local `127.0.0.1:6379`, with B dialing that machine on your behalf.

---

## 🚀 Quick Start

### Prerequisites

- Prebuilt binary: none (download and run)
- Building from source: Rust ≥ 1.85 (`cargo --version`)

### Option 1: Prebuilt Binaries (Recommended)

Download the archive for your platform from [Releases](https://github.com/steven-ld/PowerMap/releases); unpack to get the `powermap-server` and `powermap-client` binaries. Each archive ships with a `.sha256` checksum file.

| Platform | Target triple |
|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux aarch64 | `aarch64-unknown-linux-gnu` |
| macOS x86_64 (Intel) | `x86_64-apple-darwin` |
| macOS aarch64 (Apple Silicon) | `aarch64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

### Option 2: Build from Source

```bash
git clone https://github.com/steven-ld/PowerMap.git
cd PowerMap
cargo build --release
# Output: target/release/powermap-server, target/release/powermap-client
```

<details>
<summary>Can't reach crates.io? Use an alternative registry mirror</summary>

Add to `~/.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "rsproxy-sparse"
[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
```
</details>

### Three Steps to a Working Tunnel

**Step 1 · Start server B on the intranet device**

```bash
./powermap-server
```

First run generates three files in the config dir:

| File | Description |
|---|---|
| `powermap-server.key` | Node identity (**persisted, keeps node id stable**) |
| `powermap-server.toml` | Config (with a randomly generated token) |
| `powermap-server.credential.json` | **The credential — hand this to home side A** |

Subsequent starts reuse the same config; node id and token stay the same, so **A never needs a new credential**.

**Step 2 · Start client A on your home computer**

```bash
./powermap-client
```

Opens <http://127.0.0.1:8088> on launch. The web admin UI has **two pages**:

- **Port Mappings** (home): connection status, traffic metrics, add & manage mappings
- **Connection**: paste the credential to connect

On the **Connection** page, paste the whole `powermap-server.credential.json` into the "Credential JSON" box (or fill `node_id` and `token` separately) and click "Connect / Update". The credential is written to `powermap-client.toml` and **auto-restored on restart**.

<details>
<summary>You can also inject the credential via CLI (equivalent to the web form)</summary>

```bash
./powermap-client --credential /path/to/powermap-server.credential.json
```
</details>

**Step 3 · Add a mapping**

Back on the **Port Mappings** page, fill the form — or use the API:

```bash
# local 6379 → intranet 192.168.1.101:6379
curl -X POST http://127.0.0.1:8088/api/mappings \
  -H 'Content-Type: application/json' \
  -d '{"local":"127.0.0.1:6379","host":"192.168.1.101","port":6379}'

# Virtual IP: local 127.0.0.2:6379 → another intranet device
curl -X POST http://127.0.0.1:8088/api/mappings \
  -H 'Content-Type: application/json' \
  -d '{"local":"127.0.0.2:6379","host":"192.168.1.101","port":6379}'

curl http://127.0.0.1:8088/api/mappings                       # list
curl -X DELETE http://127.0.0.1:8088/api/mappings/127.0.0.1%3A6379
```

Done. `redis-cli -h 127.0.0.1 -p 6379` now talks to the intranet Redis.

---

## 🐳 Docker Deployment

The image contains both binaries; pick a side via `command`. **Server B is the ideal Docker target** — it runs on an intranet box and exposes no inbound port.

```bash
docker build -t powermap .

# powermap-server: mount ./data to persist identity & config; host network improves hole-punching
docker run -d --name powermap-server --network host \
  -v "$PWD/data:/data" \
  -e RUST_LOG=info \
  powermap powermap-server --config /data/powermap-server.toml

# Grab the credential for home side A
cat data/powermap-server.credential.json
```

Or with Compose:

```bash
docker compose up -d --build
```

> ⚠️ **Run client A natively, not in Docker**: A's mapped local ports live *inside* the container, so reaching them from the host means publishing each with `-p` — a hassle. Running A on your home machine directly is simplest.

---

## ⚙️ Configuration

Each side has its own TOML, by default in `<system config dir>/powermap/` (Linux `~/.config/powermap/`, macOS `~/Library/Application Support/powermap/`); override with `--config`. CLI flags (`--help`) take precedence over the config file.

### `powermap-client.toml` (client A)

```toml
node_id = "a5d40b0a8d24..."    # B's EndpointId
token = "991fd0a3..."          # access token generated by B
web_bind = "127.0.0.1:8088"
web_token = ""                 # admin UI access token; empty = no auth
web_tls_cert = ""              # TLS cert path (PEM)
web_tls_key = ""               # TLS key path (PEM)
max_mappings = 256             # cap on number of mappings
max_conns_per_mapping = 512    # max concurrent conns per mapping (0 = unlimited)

[[mappings]]
local = "127.0.0.1:6379"
host = "192.168.1.101"
port = 6379
```

| Field | Description | Default |
|---|---|---|
| `node_id` | B's EndpointId | - |
| `token` | Access token generated by B | - |
| `web_bind` | Admin UI listen address | `127.0.0.1:8088` |
| `web_token` | Admin UI token; empty = no auth (**must set** when binding `0.0.0.0` for remote admin) | `""` |
| `web_tls_cert` / `web_tls_key` | Both non-empty enables HTTPS | `""` |
| `max_mappings` | Max mappings, prevents exhausting local ports | `256` |
| `max_conns_per_mapping` | Max concurrent conns per mapping (0 = unlimited) | `512` |

### `powermap-server.toml` (server B · single-tenant)

```toml
identity = "powermap-server.key"   # relative to this config file's dir
token = "991fd0a3..."              # if empty and no clients, generated & written back on first run
allow_networks = []                # dial-able target networks (CIDR); empty = allow all
allow_ports = []                   # dial-able target ports; empty = allow all
max_streams_per_conn = 256         # max concurrent tunnels per conn (0 = unlimited)
dial_timeout_secs = 10             # intranet dial timeout (seconds)
audit_log = ""                     # audit log file path; empty = tracing only
```

### `powermap-server.toml` (server B · multi-tenant)

Use `[[clients]]` to give each client its own token and allowlist, rotatable / revocable individually:

```toml
identity = "powermap-server.key"
max_streams_per_conn = 256
dial_timeout_secs = 10
audit_log = "/var/log/powermap/audit.jsonl"

[[clients]]
id = "alice"                       # client id for audit logs & metric labels (not secret)
token = "alice-token-..."
allow_networks = ["192.168.1.0/24"]
allow_ports = [6379, 5432]
max_streams = 32                   # this client's max concurrent tunnels (0 = unlimited)

[[clients]]
id = "bob"
token = "bob-token-..."
allow_networks = ["10.0.0.0/8"]
revoked = true                     # revoked: kept for audit trail, but connection refused
```

> A top-level single `token` is normalized to a client with id `default` and can coexist with `[[clients]]` — so old configs keep working unchanged. Rotating or revoking a client requires a **restart of B**.

---

## 🔐 Security

| Mechanism | Description |
|---|---|
| **Access credential** | `token` is the only way in, compared in constant time to prevent timing side-channels. Anyone with `node_id + token` can make B dial inside its intranet — guard `credential.json` like a password |
| **End-to-end encryption** | QUIC + rustls throughout (iroh built-in); relays only forward ciphertext |
| **Target allowlist** | `allow_networks` (CIDR) + `allow_ports` limit dial-able range. B **resolves the hostname once and dials only allowlist-passing IPs**, closing the DNS-rebinding (TOCTOU) bypass |
| **Multi-tenant isolation** | `[[clients]]` issues per-user tokens with their own allowlists and caps; `revoked = true` revokes one without affecting others |
| **Audit logging** | Each dial (allowed / denied / timeout / failed) writes one JSON line with timestamp, client id, target, result |
| **Resource caps** | `max_streams_per_conn`, per-client `max_streams`, `dial_timeout_secs`, plus A-side `max_mappings` / `max_conns_per_mapping` prevent resource exhaustion |
| **Admin UI auth** | With `web_token` set, all APIs require `Authorization: Bearer <token>` or `?token=`; must set when binding `0.0.0.0` for remote admin |
| **Admin UI HTTPS** | Set both `web_tls_cert` and `web_tls_key` to enable TLS |

---

## 📊 Observability & Ops

**Prometheus metrics** — A-side `/metrics`, plain text, scrape directly:

```bash
curl http://127.0.0.1:8088/metrics
```

Exposes tunnel counts (opened / active / failed), handshake and target-rejection counts, over-limits, dial failures / timeouts, reconnects, bytes in/out, etc. `/metrics` and `/api/health` are **unauthenticated** (aggregate counts only, no secrets); restrict source at a reverse proxy if binding `0.0.0.0`. B exposes no inbound port and instead **logs metrics into tracing periodically (60s)**.

**Graceful shutdown** — on `SIGINT` / `SIGTERM`, A stops accepting new connections and **drains in-flight tunnels** via a `CancellationToken` before exiting; a runtime `DELETE` of a mapping also actively closes that mapping's in-flight connections.

---

## 🔬 How It Works

```mermaid
sequenceDiagram
    participant App as Local client<br/>(redis-cli etc.)
    participant A as powermap-client (A)
    participant Relay as iroh relay / DNS
    participant B as powermap-server (B)
    participant Target as Intranet target<br/>(192.168.1.101:6379)

    Note over B,Relay: Startup: bind node identity, register relay, expose ALPN /powermap/tcp/0
    A->>Relay: Discover B by node_id
    Relay-->>A: Locate via relay + DNS
    A->>B: Hole-punch a QUIC connection (mostly direct, relay on fallback)
    Note over A,B: Connection kept and reused long-term

    App->>A: TCP connect to the mapped local port
    A->>B: Open a QUIC bidi stream on the reused connection<br/>handshake header {token, host, port}
    B->>B: Validate token + allowlist (CIDR / port)
    B->>Target: Dial host:port on the intranet
    Target-->>B: Connection ready
    B-->>A: Status 0 (success)
    App->>Target: Bidirectional TCP relay (half-close supported)

    Note over A,B: Watchdog keeps the hot connection; reconnects with exponential backoff (1→30s + jitter)
```

1. B binds a node identity via iroh, registers with the N0 relay network, and exposes ALPN `/powermap/tcp/0`.
2. With just B's `node_id`, A discovers B via relay + DNS and hole-punches (direct in most cases, relay when it can't).
3. Each mapping = one TCP listener on A. For every incoming connection, A **reuses the same iroh connection to B** and opens a QUIC bidirectional stream (QUIC multiplexes natively), with `{token, host, port}` in the handshake header.
4. B validates the token, checks the target against the allowlist, dials `host:port` on the intranet, then relays TCP bidirectionally with **half-close** support (HTTP keep-alive etc. work correctly).
5. A background **watchdog** keeps the hot connection alive and reconnects on drop with exponential backoff (1→30s + jitter); both ends use 5s keepalive + 15s idle timeout, so a lost peer is noticed within ~15s.

> QUIC transport tuned: per-connection concurrent bidi-stream limit raised to 1024, flow windows enlarged, paired with 64KB forwarding buffers to sustain throughput under many concurrent mappings.

---

## 🩺 Troubleshooting

| Symptom | Fix |
|---|---|
| A can't connect / `B refused` | Confirm `node_id` and `token` match B (see `powermap-server.credential.json`) |
| `Failed to connect to relay server: timeout` | N0 relay hiccups occasionally; iroh auto-switches relays (e.g. `euc1` → `aps1`). The first tunnel may take a few extra seconds or one retry (A has one built-in) |
| Local port bind fails | Port in use; change it, or check for an existing mapping with the same name |
| Config change has no effect | Config is read only at startup; add/remove mappings at runtime via Web/API (auto-written back). Changing B's `[[clients]]` requires a **restart of B** |
| Don't want `/metrics` publicly visible | It's unauthenticated (aggregate counts only); restrict scrape source at a reverse proxy when binding `0.0.0.0` |

---

## 🧭 Limitations

- The credential carries only `node_id`; connecting relies on iroh's relay / DNS discovery. Under extreme NAT where discovery struggles, consider carrying a full `EndpointAddr` (relay URL + direct addresses).
- Each local TCP connection on A opens a stream over the shared iroh connection; a dropped connection reconnects lazily, but established tunnels break with it and need a client reconnect.

---

## 🛠️ Development

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

CI ([`ci.yml`](.github/workflows/ci.yml)) runs fmt + clippy (`-D warnings`) + test on every push / PR. See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.

### Releasing

Pushing a `v1.2.3`-style tag triggers [`release.yml`](.github/workflows/release.yml), cross-compiling for all 5 platforms and uploading archives + checksums to the matching GitHub Release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

---

## 📄 License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project (as defined in Apache-2.0) shall be dual-licensed as above, without any additional terms.
