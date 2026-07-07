#!/usr/bin/env bash
# Build container images for RedTeam Platform tools
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Building redteam-nmap:latest ==="
docker build -t redteam-nmap:latest "$PROJECT_ROOT/containers/nmap/"

echo ""
echo "=== Build complete ==="
echo "To save for offline distribution:"
echo "  docker save -o $PROJECT_ROOT/containers/nmap.tar redteam-nmap:latest"
