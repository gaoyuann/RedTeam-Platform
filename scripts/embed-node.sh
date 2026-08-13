#!/usr/bin/env bash
# Download and embed Node.js runtime into the dist directory
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_ROOT/dist/RedTeam-Platform"

NODE_VERSION="${1:-v22.10.0}"
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] && NODE_ARCH="x64" || NODE_ARCH="arm64"

NODE_TAR="node-${NODE_VERSION}-linux-${NODE_ARCH}"
NODE_URL="https://nodejs.org/dist/${NODE_VERSION}/${NODE_TAR}.tar.xz"

echo "=== Embed Node.js Runtime ==="
echo "Version: $NODE_VERSION"
echo "Arch: $NODE_ARCH"

mkdir -p "$DIST_DIR/node"

# Download
TMPDIR="$(mktemp -d)"
echo "Downloading $NODE_URL ..."
curl -fSL -o "$TMPDIR/node.tar.xz" "$NODE_URL"

# Extract only bin/node and bin/npm
echo "Extracting..."
tar xf "$TMPDIR/node.tar.xz" -C "$TMPDIR" --strip-components=1
cp "$TMPDIR/bin/node" "$DIST_DIR/node/node"
cp "$TMPDIR/bin/npm" "$DIST_DIR/node/npm" 2>/dev/null || true
chmod +x "$DIST_DIR/node/node" "$DIST_DIR/node/npm" 2>/dev/null || true

rm -rf "$TMPDIR"

# Verify
EMBEDDED_VERSION="$("$DIST_DIR/node/node" --version 2>/dev/null || echo 'N/A')"
echo "Embedded Node.js: $EMBEDDED_VERSION"
echo "Path: $DIST_DIR/node/node"
