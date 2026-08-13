#!/usr/bin/env bash
# RedTeam Platform - Client start script
# Runs on cloud laptops (云笔电, ARM64 飞腾, 银河麒麟/UOS)
# Starts: Qt5 frontend only — connects to server via network
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Detect mode ────────────────────────────────────────────────────────
if [ -x "$SCRIPT_DIR/bin/RedTeam-Platform" ]; then
  # Portable bundle mode
  FRONTEND_BIN="$SCRIPT_DIR/bin/RedTeam-Platform"
  QT_LIB_DIR="$SCRIPT_DIR/lib/qt"
  QT_SSL_DIR="$SCRIPT_DIR/lib/openssl"
  QT_PLUGIN_DIR="$SCRIPT_DIR/plugins"
  FONT_DIR="$SCRIPT_DIR/fonts"
else
  # Development mode
  BASE_DIR="$(dirname "$SCRIPT_DIR")"
  FRONTEND_BIN="$BASE_DIR/build/frontend/RedTeam-Platform"
  QT_LIB_DIR=""
  QT_SSL_DIR=""
  QT_PLUGIN_DIR=""
  FONT_DIR=""
fi

# ── Server address ─────────────────────────────────────────────────────
# Priority: command line arg > env variable > interactive input > default
SERVER="${1:-${REDTEAM_SERVER:-}}"

if [ -z "$SERVER" ]; then
  # Try QSettings from a previous session
  if command -v gsettings &>/dev/null; then
    # No reliable way to read Qt QSettings from shell, skip
    :
  fi
  read -p "请输入服务器地址 (IP:端口, 默认 127.0.0.1:3002): " input
  SERVER="${input:-127.0.0.1:3002}"
fi

echo "=== RedTeam Platform Client ==="
echo "Server: $SERVER"
echo "Frontend: $FRONTEND_BIN"

# ── Set library paths ──────────────────────────────────────────────────
if [ -n "$QT_LIB_DIR" ] && [ -d "$QT_LIB_DIR" ]; then
  export LD_LIBRARY_PATH="$QT_LIB_DIR${QT_SSL_DIR:+:$QT_SSL_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  echo "[env] LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
fi
if [ -n "$QT_PLUGIN_DIR" ] && [ -d "$QT_PLUGIN_DIR" ]; then
  export QT_PLUGIN_PATH="$QT_PLUGIN_DIR"
  export QT_QPA_PLATFORM_PLUGIN_PATH="$QT_PLUGIN_DIR/platforms"
  echo "[env] QT_PLUGIN_PATH=$QT_PLUGIN_PATH"
fi

# ── Start frontend ─────────────────────────────────────────────────────
echo "Starting Qt frontend..."
if [ -x "$FRONTEND_BIN" ]; then
  exec "$FRONTEND_BIN" --server "$SERVER"
else
  echo "ERROR: Frontend binary not found at $FRONTEND_BIN"
  echo "Build first: cmake -B build -S . && cmake --build build"
  exit 1
fi
