# Build the container from the already verified GitHub Release artifact. The release workflow
# uploads and smoke-tests this archive before it reaches this Docker build, so QEMU never has to
# compile Rust a second time for linux/arm64.
FROM debian:bookworm-slim

ARG VERSION=latest
ARG TARGETARCH
ARG REPOSITORY=steven-ld/PowerMap

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar && \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported Docker architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    archive="powermap-${target}.tar.gz"; \
    checksum="powermap-${target}.sha256"; \
    if [ "$VERSION" = latest ]; then base="https://github.com/$REPOSITORY/releases/latest/download"; \
    else base="https://github.com/$REPOSITORY/releases/download/$VERSION"; fi; \
    cd /tmp; \
    curl --fail --location --retry 3 --output "$archive" "$base/$archive"; \
    curl --fail --location --retry 3 --output "$checksum" "$base/$checksum"; \
    sha256sum -c "$checksum"; \
    tar -xzf "$archive"; \
    install -m 0755 powermap /usr/local/bin/powermap; \
    rm -f "$archive" "$checksum" powermap LICENSE-MIT LICENSE-APACHE README.md

WORKDIR /app
ENTRYPOINT ["sh", "-c", "exec \"$@\"", "--"]
CMD ["powermap", "--help"]
