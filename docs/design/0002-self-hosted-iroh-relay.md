# Design 0002: Self-hosted Iroh Relay

- Status: accepted and implemented
- Applies to: PowerMap v0.8.x and the separately released `powermap-relay`

## Decision

PowerMap will ship an upstream-compatible `iroh-relay` as a separate release artifact and Docker
image. Each customer deployment may run one or more of these relays. Relay configuration is
absent by default, so existing PowerMap installations continue to use iroh's default relay map.

The relay is a fallback transport, not a terminating proxy: iroh's QUIC and rustls encryption
remains end to end, while PowerMap's expose token and target allowlist remain the access-control
boundary for private services.

## Current-State Findings

| Area | Finding | Design consequence |
| --- | --- | --- |
| Endpoint construction | Both roles start from `Endpoint::builder(presets::N0)` and then apply the root relay mode. | Both roles use the same custom relay map when URLs are configured. |
| Configuration | Root `[relay]` supports up to eight unique HTTPS URLs and an optional bearer token. | An empty URL list keeps iroh's default relay-mode selection, including its staging override. |
| Peer discovery | N0 PKARR/DNS lookup remains enabled while relay transport is replaced. | This phase does not operate separate discovery infrastructure; explicit credential sharing applies the peer's relay configuration to the receiving access node. |
| Transport health | Access already reports direct/relay path, RTT, and the selected relay host. | Add relay-selection and failover diagnostics instead of inventing a second health plane. |
| Delivery | The repository already builds verified native archives and multi-architecture Docker images. | The relay gets a parallel Linux-only archive/image path, not a second repository. |

## Topology

```mermaid
flowchart LR
    A["PowerMap access node"] -->|"direct QUIC when possible" B["PowerMap expose node"]
    A <-->|"encrypted fallback" R1["Customer relay A"]
    B <-->|"encrypted fallback" R1
    A <-->|"encrypted fallback after failover" R2["Customer relay B"]
    B <-->|"encrypted fallback after failover" R2
    M["Private Prometheus collector"] -->|"loopback only" R1
    M -->|"loopback only" R2
```

Deploy at least two relay instances only where the customer's availability target needs it. Put
them in independent failure domains, give each a DNS name and valid certificate, and publish
TCP `80`, TCP `443`, and UDP `7842`. The relay uses TCP `443` for its HTTPS transport and UDP
`7842` for QUIC address discovery; TCP `80` is needed for HTTP-01 certificate issuance.

## Relay Delivery

`relay/Dockerfile` builds `iroh-relay 1.0.2` with the upstream server feature and offers an
`artifact` target for release archives. `relay/docker-compose.yml` runs a hardened, non-root
container with only `NET_BIND_SERVICE`, persistent certificate state, and loopback-only metrics.
`relay/relay.toml.example` enables TLS, QUIC address discovery, rate limiting, and a dedicated
relay bearer token.

The Release workflow builds and checks AMD64 and ARM64 Linux archives, then publishes a matching
multi-architecture image. The relay token is distinct from the PowerMap connection token: it
protects relay bandwidth but grants no permission to reach a private service.

## Application Behaviour

1. `[relay]` is a root setting shared by `access` and `expose`. It is validated as a bounded set
   of unique HTTPS relay URLs; an auth token without URLs is rejected.
2. Empty URLs use iroh's default relay mode. Configured URLs construct `RelayMode::Custom(RelayMap)`
   and apply the optional bearer token to every relay in the map.
3. The Nodes page applies relay changes to the running access endpoint and invalidates only its
   cached connection. The next connection uses the new map. Expose reads the same setting at
   startup, so an expose endpoint needs a process restart after a UI change.
4. Credentials may carry an optional `relay` object. It is absent by default and the receiving
   access node retains its local relay settings. The UI adds it only after the operator explicitly
   selects sharing, since it can contain the bearer token.
5. N0 PKARR/DNS address lookup remains enabled during this phase. A separately operated
   discovery service and live expose relay reconfiguration remain future work.

## Non-goals

- PowerMap is not operating a shared public relay network.
- A relay does not inspect tunnel contents or replace PowerMap authorization.
- The first phase does not build a self-hosted PKARR/DNS discovery service.
