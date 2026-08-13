#!/bin/bash
# Export all RedTeam-Platform container images as tar files for offline distribution
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENGINE="${CONTAINER_ENGINE:-docker}"
OUTDIR="$PROJECT_ROOT/containers/tar"

mkdir -p "$OUTDIR"

IMAGES="rt-recon rt-vuln-scan rt-brute rt-system rt-exploit rt-web rt-credential rt-cloud"

echo "=== Exporting images to $OUTDIR/ ==="

for img in $IMAGES; do
  # Check if image exists
  if $ENGINE images --format '{{.Repository}}' | grep -q "^${img}$"; then
    echo "Exporting ${img}..."
    $ENGINE save -o "$OUTDIR/${img}.tar" "${img}:latest"
    SIZE=$(du -h "$OUTDIR/${img}.tar" | cut -f1)
    echo "  → ${img}.tar ($SIZE)"
  else
    echo "Skipping ${img} (not built)"
  fi
done

echo ""
echo "=== Export complete ==="
ls -lh "$OUTDIR/"*.tar 2>/dev/null || echo "No tar files found"
