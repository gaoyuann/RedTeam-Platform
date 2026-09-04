#!/usr/bin/env bash
# RedTeam Platform - One-click start script
# Works in both development mode (from scripts/) and portable bundle mode (from dist/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Detect mode ────────────────────────────────────────────────────────
if [ -x "$SCRIPT_DIR/bin/RedTeam-Platform" ]; then
  # Portable bundle mode
  BASE_DIR="$SCRIPT_DIR"
  FRONTEND_BIN="$BASE_DIR/bin/RedTeam-Platform"
  BACKEND_DIR="$BASE_DIR/backend"
  DATA_DIR="$BASE_DIR/data"
  NODE_BIN="$BASE_DIR/node/node"
  QT_LIB_DIR="$BASE_DIR/lib/qt"
  QT_SSL_DIR="$BASE_DIR/lib/openssl"
  QT_PLUGIN_DIR="$BASE_DIR/plugins"
  FONT_DIR="$BASE_DIR/fonts"
else
  # Development mode
  BASE_DIR="$(dirname "$SCRIPT_DIR")"
  FRONTEND_BIN="$BASE_DIR/build/frontend/RedTeam-Platform"
  BACKEND_DIR="$BASE_DIR/backend"
  DATA_DIR="$BASE_DIR/data"
  NODE_BIN="node"  # Use system node
  QT_LIB_DIR=""
  QT_SSL_DIR=""
  QT_PLUGIN_DIR=""
  FONT_DIR=""
fi

HEALTH_URL="http://127.0.0.1:3002/api/health"
MAX_WAIT=30

echo "=== RedTeam Platform Start ==="
echo "Mode: $([ -x "$SCRIPT_DIR/bin/RedTeam-Platform" ] && echo 'portable' || echo 'development')"

# ── 0. Input Method (IME) setup ───────────────────────────────────────
# Auto-detect and configure Chinese input method for Qt5 on Linux/X11.
# Priority: fcitx5 > fcitx > ibus. Must be set BEFORE the Qt app starts.

# 0a. Ensure D-Bus session bus is available (WSL2 often lacks this)
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] || [ ! -S "${DBUS_SESSION_BUS_ADDRESS#unix:path=}" ]; then
  if command -v dbus-launch >/dev/null 2>&1; then
    eval "$(dbus-launch --sh-syntax)"
    export DBUS_SESSION_BUS_ADDRESS
    echo "[env] D-Bus session bus started"
  fi
fi

# 0b. Detect / start IME framework
if [ -z "${QT_IM_MODULE:-}" ]; then
  if pgrep -x fcitx5 >/dev/null 2>&1; then
    export QT_IM_MODULE=fcitx
    export GTK_IM_MODULE=fcitx
    export XMODIFIERS=@im=fcitx
    echo "[env] IME: fcitx5 (detected running)"
  elif pgrep -x fcitx >/dev/null 2>&1; then
    export QT_IM_MODULE=fcitx
    export GTK_IM_MODULE=fcitx
    export XMODIFIERS=@im=fcitx
    echo "[env] IME: fcitx (detected running)"
  elif pgrep -x ibus-daemon >/dev/null 2>&1; then
    export QT_IM_MODULE=ibus
    export GTK_IM_MODULE=ibus
    export XMODIFIERS=@im=ibus
    echo "[env] IME: ibus (detected running)"
  elif command -v fcitx5 >/dev/null 2>&1; then
    # fcitx5 installed but not running — auto-start
    echo "[env] Starting fcitx5..."
    fcitx5 -d 2>/dev/null &>/dev/null || true
    sleep 1
    if pgrep -x fcitx5 >/dev/null 2>&1; then
      export QT_IM_MODULE=fcitx
      export GTK_IM_MODULE=fcitx
      export XMODIFIERS=@im=fcitx
      echo "[env] IME: fcitx5 (auto-started)"
    else
      echo "[env] WARNING: fcitx5 auto-start failed (needs D-Bus + X11 session)"
      echo "       Hint: run 'fcitx5 -d' in your desktop terminal first"
      export QT_IM_MODULE=ibus
      export GTK_IM_MODULE=ibus
      export XMODIFIERS=@im=ibus
    fi
  else
    export QT_IM_MODULE=ibus
    export GTK_IM_MODULE=ibus
    export XMODIFIERS=@im=ibus
    echo "[env] IME: ibus (default — run 'sudo bash scripts/setup-ime.sh' to install fcitx5)"
  fi
fi

# ── 1. Set library paths ──────────────────────────────────────────────
if [ -n "$QT_LIB_DIR" ] && [ -d "$QT_LIB_DIR" ]; then
  export LD_LIBRARY_PATH="$QT_LIB_DIR${QT_SSL_DIR:+:$QT_SSL_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  echo "[env] LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
fi
if [ -n "$QT_PLUGIN_DIR" ] && [ -d "$QT_PLUGIN_DIR" ]; then
  export QT_PLUGIN_PATH="$QT_PLUGIN_DIR"
  export QT_QPA_PLATFORM_PLUGIN_PATH="$QT_PLUGIN_DIR/platforms"
  echo "[env] QT_PLUGIN_PATH=$QT_PLUGIN_PATH"
fi

# ── 2. Start backend ──────────────────────────────────────────────────
echo "[1/3] Starting Node.js backend..."
cd "$BACKEND_DIR"

# Set data directory for SQLite
export REDTEAM_DATA_DIR="$DATA_DIR"
# Single-machine mode: bind to localhost
export HOST="127.0.0.1"

"$NODE_BIN" src/server.js &
BACKEND_PID=$!
echo "       Backend PID: $BACKEND_PID (node: $("$NODE_BIN" --version 2>/dev/null || echo 'system'))"

# Ensure backend is killed on any exit (window close, Ctrl+C, etc.)
trap 'echo "Stopping backend (PID $BACKEND_PID)..."; kill $BACKEND_PID 2>/dev/null || true; wait $BACKEND_PID 2>/dev/null || true' EXIT HUP INT TERM

# ── 3. Wait for backend health ────────────────────────────────────────
echo "[2/3] Waiting for backend to become ready..."
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
    echo "       Backend ready after ${WAITED}s"
    break
  fi
  sleep 1
  WAITED=$((WAITED + 1))
done

if [ $WAITED -ge $MAX_WAIT ]; then
  echo "ERROR: Backend did not become ready within ${MAX_WAIT}s"
  kill $BACKEND_PID 2>/dev/null || true
  exit 1
fi

# ── 4. Start Qt frontend ──────────────────────────────────────────────
echo "[3/3] Starting Qt frontend..."
if [ -x "$FRONTEND_BIN" ]; then
  "$FRONTEND_BIN"
  EXIT_CODE=$?
else
  echo "ERROR: Frontend binary not found at $FRONTEND_BIN"
  EXIT_CODE=1
fi

# ── Cleanup ───────────────────────────────────────────────────────────
echo "Stopping backend (PID $BACKEND_PID)..."
kill $BACKEND_PID 2>/dev/null || true
exit $EXIT_CODE
