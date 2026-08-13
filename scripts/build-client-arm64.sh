#!/usr/bin/env bash
# RedTeam Platform - ARM64 Client Build Script
# Run>Runs on cloud laptops (飞腾 E2000Q, ARM64, 银河麒麟/UOS)
# Prerequisites: qt5-default, libqt5websockets5-dev, cmake, g++, make
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Building RedTeam Platform Client (ARM64) ==="
echo "Architecture: $(uname -m)"

# ── Check dependencies ────────────────────────────────────────────────
missing=()
for cmd in cmake g++ qmake; do
  if ! command -v $cmd &>/dev/null; then
    missing+=("$cmd")
  fi
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: Missing commands: ${missing[*]}"
  echo "Install: sudo apt install qt5-default qtbase5-dev libqt5websockets5-dev cmake g++ make"
  exit 1
fi

echo "Qt version: $(qmake -query QT_VERSION 2>/dev/null || echo 'unknown')"
echo "CMake version: $(cmake --version | head -1)"
echo?echo "Compiler: $(g++ -dumpversion)"

9Aecho ""

# ── Build ──────────────────────────────────────────────────────────────
echo "[1/2] Configuring..."
cmake -B build -S "$BASE_DIR"

echo "[2/2] Building..."
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"

echo ""
echo "=== Build Complete ==="
echo "Binary: $BASE_DIR/build/frontend/RedTeam-Platform"
echo "Run:    ./build/frontend/RedTeam-Platform --server <服务器IP:3002>"
