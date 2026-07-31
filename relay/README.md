# PowerMap Relay

This directory packages the upstream `iroh-relay` server as a separate PowerMap delivery
artifact. It is not part of the `powermap` process or application container. Use it when a
deployment needs to replace PowerMap's built-in official relay with a private primary relay set.

## Deploy

Use a Linux host with a public IPv4 or IPv6 address and a DNS record such as
`relay.example.com` pointing to it. Open TCP `80`, TCP `443`, and UDP `7842` in the host and
cloud firewalls. Keep TCP `9090` private; the Compose file only publishes it on loopback.

```bash
mkdir -p powermap-relay/state
cd powermap-relay
cp /path/to/PowerMap/relay/relay.toml.example relay.toml
# Edit relay.toml: set tls.hostname, tls.contact, and access.shared_token.
sudo chown -R 10001:10001 state
POWERMAP_RELAY_TAG=v0.9.0 \
POWERMAP_RELAY_CONFIG="$(pwd)/relay.toml" \
POWERMAP_RELAY_STATE_DIR="$(pwd)/state" \
docker compose -f /path/to/PowerMap/relay/docker-compose.yml up -d
```

The container obtains and persists the Let's Encrypt certificate under `state/`. The health
endpoint is `/healthz`; metrics remain available only to local collectors at
`http://127.0.0.1:9090/metrics`.

Do not put a normal HTTP reverse proxy in front of TCP `443`: the relay owns its TLS endpoint
and the QUIC address-discovery service requires direct UDP `7842` reachability. A managed
load balancer is acceptable only when it preserves TCP `443`, UDP `7842`, the TLS certificate
behavior, and source-independent health checks.

## Release Artifacts

Each PowerMap release publishes these independently from the application binaries:

- `powermap-relay-x86_64-unknown-linux-gnu.tar.gz`
- `powermap-relay-aarch64-unknown-linux-gnu.tar.gz`
- Matching `.sha256` checksum files
- `ghcr.io/<owner>/powermap-relay:<tag>` and `:latest` images for Linux AMD64 and ARM64

The relay binary is pinned to `iroh-relay 1.0.2`, the version currently used transitively by
PowerMap's locked `iroh 1.0.2` dependency. Upgrade the two together after compatibility tests.

## Application Integration

Configure the same HTTPS relay entries on both PowerMap endpoints, either in the dedicated Relay
page or as the root `[relay]` section in `powermap.toml`. Each entry carries its own optional
relay token. Empty entries keep PowerMap's official relay as the primary relay; iroh's default map
is dynamically added only if the primary set fails. The Relay page can measure each saved entry's
DNS, TLS, and HTTP latency through `GET /ping`; this control-plane probe does not validate relay
admission. The Local-node copy control can explicitly include relay settings in a credential JSON
for the receiving access node; this is intentionally opt-in because it includes private relay
tokens and the forced-relay choice. Relay tokens limit relay usage only and never grant access to
private services.
