#!/usr/bin/env sh
# Install a released PowerMap client and server archive without requiring root.
set -eu

REPOSITORY="steven-ld/PowerMap"
VERSION="${POWERMAP_VERSION:-${1:-latest}}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *)
    echo "Unsupported operating system: $(uname -s). Download a release manually." >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *)
    echo "Unsupported architecture: $(uname -m). Download a release manually." >&2
    exit 1
    ;;
esac

target="${arch}-${os}"
archive="powermap-${target}.tar.gz"

case "$VERSION" in
  latest)
    base_url="https://github.com/${REPOSITORY}/releases/latest/download"
    release_page="https://github.com/${REPOSITORY}/releases/latest"
    ;;
  v*)
    base_url="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
    release_page="https://github.com/${REPOSITORY}/releases/tag/${VERSION}"
    ;;
  *)
    echo "Version must be 'latest' or a tag beginning with v (for example v0.1.0)." >&2
    exit 1
    ;;
esac

for command in curl tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 1
  }
done

if command -v shasum >/dev/null 2>&1; then
  checksum_command='shasum -a 256 -c'
elif command -v sha256sum >/dev/null 2>&1; then
  checksum_command='sha256sum -c'
else
  echo "Missing required checksum command: shasum or sha256sum" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT HUP INT TERM

download_asset() {
  asset="$1"

  if ! curl --fail --location --retry 3 --silent --output "$tmpdir/$asset" "$base_url/$asset"; then
    echo "Unable to download $asset for $target from PowerMap $VERSION." >&2
    echo "The release may not include assets for this platform yet, or the network request failed." >&2
    echo "Release page: $release_page" >&2
    if [ "$VERSION" = "latest" ]; then
      echo "Retry shortly, or install a published version explicitly: sh install.sh v0.2.0" >&2
    fi
    exit 1
  fi
}

echo "Downloading PowerMap ${VERSION} for ${target}..."
download_asset "$archive"
download_asset "powermap-$target.sha256"

(
  cd "$tmpdir"
  $checksum_command "powermap-$target.sha256"
)

tar -xzf "$tmpdir/$archive" -C "$tmpdir"
mkdir -p "$INSTALL_DIR"
install -m 755 "$tmpdir/powermap-server" "$INSTALL_DIR/powermap-server"
install -m 755 "$tmpdir/powermap-client" "$INSTALL_DIR/powermap-client"

echo "Installed powermap-server and powermap-client to $INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add $INSTALL_DIR to PATH to run PowerMap without an absolute path." ;;
esac
