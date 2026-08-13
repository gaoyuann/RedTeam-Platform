#!/bin/bash
# Build all RedTeam-Platform container images
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTAINERS_DIR="$PROJECT_ROOT/containers"
ENGINE="${CONTAINER_ENGINE:-docker}"

echo "=== RedTeam-Platform: Building container images with $ENGINE ==="

IMAGES="recon vuln-scan brute system exploit web credential cloud"

for img in $IMAGES; do
  dir="$CONTAINERS_DIR/$img"
  if [ -f "$dir/Dockerfile" ]; then
    echo ""
    echo "--- Building rt-$img ---"
    $ENGINE build -t "rt-$img:latest" "$dir"
  else
    echo "--- Skipping rt-$img (no Dockerfile) ---"
  fi
done

echo ""
echo "=== Build complete ==="
$ENGINE images | grep "^rt-"
