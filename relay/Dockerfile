# syntax=docker/dockerfile:1.7
# Keep the relay binary independent from the PowerMap application image.  The version is
# pinned to the iroh-relay version currently resolved by PowerMap's Cargo.lock.
FROM rust:1.91-bookworm AS build

ARG IROH_RELAY_VERSION=1.0.2

RUN cargo install \
    --locked \
    --version "=${IROH_RELAY_VERSION}" \
    --features server \
    --root /out \
    iroh-relay

# Used by the release workflow to export a native binary archive.
FROM scratch AS artifact
COPY --from=build /out/bin/iroh-relay /iroh-relay

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 relay \
    && useradd --uid 10001 --gid relay --create-home --home-dir /var/lib/iroh-relay relay

COPY --from=build /out/bin/iroh-relay /usr/local/bin/iroh-relay

USER 10001:10001
WORKDIR /var/lib/iroh-relay

EXPOSE 80/tcp 443/tcp 7842/udp 9090/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error --insecure https://127.0.0.1/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/iroh-relay"]
CMD ["--config-path", "/etc/iroh-relay/relay.toml"]
