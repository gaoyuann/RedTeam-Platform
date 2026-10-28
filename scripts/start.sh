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

BACKEND_PORT=3002
HEALTH_URL="http://127.0.0.1:$BACKEND_PORT/api/health"
MAX_WAIT=30

# Load connection settings only into the backend, without executing an env file.
# Explicit selection wins; keep the existing local development setup compatible.
if [ -z "${REDTEAM_CSCAN_ENV_FILE:-}" ]; then
  for candidate in "${XDG_CONFIG_HOME:-$HOME/.config}/redteam/cscan.env" "$BASE_DIR/.codex/local-demo/cscan.env"; do
    if [ -f "$candidate" ]; then
      export REDTEAM_CSCAN_ENV_FILE="$candidate"
      break
    fi
  done
fi

echo "=== RedTeam Platform Start ==="
echo "Mode: $([ -x "$SCRIPT_DIR/bin/RedTeam-Platform" ] && echo 'portable' || echo 'development')"

# ── 0. Input Method (IME) setup ───────────────────────────────────────
# Auto-detect and configure Chinese input method for Qt5 on Linux/X11.
# Priority: fcitx5 > fcitx > ibus. Must be set BEFORE the Qt app starts.

# 0a. Probe the bus instead of treating an abstract D-Bus address as a file.
if ! dbus-send --session --print-reply --reply-timeout=1500 \
    --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
  if command -v dbus-launch >/dev/null 2>&1; then
    eval "$(dbus-launch --sh-syntax)"
    export DBUS_SESSION_BUS_ADDRESS
    echo "[env] D-Bus session bus started"
  fi
fi

# 0b. Select the framework, respecting an explicitly configured module.
if [ -z "${QT_IM_MODULE:-}" ]; then
  if pgrep -u "$(id -u)" -x fcitx5 >/dev/null 2>&1 || pgrep -u "$(id -u)" -x fcitx >/dev/null 2>&1; then
    export QT_IM_MODULE=fcitx GTK_IM_MODULE=fcitx XMODIFIERS=@im=fcitx
  elif pgrep -u "$(id -u)" -x ibus-daemon >/dev/null 2>&1; then
    export QT_IM_MODULE=ibus GTK_IM_MODULE=ibus XMODIFIERS=@im=ibus
  elif command -v fcitx5 >/dev/null 2>&1; then
    export QT_IM_MODULE=fcitx GTK_IM_MODULE=fcitx XMODIFIERS=@im=fcitx
  else
    export QT_IM_MODULE=ibus GTK_IM_MODULE=ibus XMODIFIERS=@im=ibus
  fi
fi

# Setting QT_IM_MODULE does not start the daemon. Check even when it was set.
if [ "${QT_IM_MODULE:-}" = fcitx ] && command -v fcitx5 >/dev/null 2>&1; then
  if ! pgrep -u "$(id -u)" -x fcitx5 >/dev/null 2>&1 && \
     ! pgrep -u "$(id -u)" -x fcitx >/dev/null 2>&1; then
    ime_args=(-d)
    # WSLg's Wayland IM connection can disappear immediately. The X11 Qt
    # client needs only the X11 backend; do not affect native Wayland desktops.
    if [[ "$(uname -r)" == *microsoft* ]] && [ -n "${DISPLAY:-}" ] && \
       [ "${QT_QPA_PLATFORM:-xcb}" = xcb ]; then
      ime_args+=(--disable=wayland,waylandim)
    fi
    echo "[env] Starting fcitx5 for this desktop session..."
    fcitx5 "${ime_args[@]}" >/dev/null 2>&1 || true
    sleep 1
  fi
  if command -v fcitx5-remote >/dev/null 2>&1 && \
     pgrep -u "$(id -u)" -x fcitx5 >/dev/null 2>&1 && \
     ! fcitx5-remote >/dev/null 2>&1; then
    echo "[env] WARNING: fcitx5 is not reachable on this D-Bus session"
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

# ── 1b. Clean up leftovers from a previous run ────────────────────────
# The EXIT trap only cleans up our own children; a previous run killed with
# SIGKILL (or a closed terminal) leaves orphans behind. Kill stale frontend
# instances first (exact /proc/exe match — pkill -f would misfire on linker
# command lines), then whatever node process still holds the backend port.

for d in /proc/[0-9]*; do
  if [ "$(readlink "$d/exe" 2>/dev/null)" = "$FRONTEND_BIN" ]; then
    echo "[clean] Stopping stale frontend (PID ${d#/proc/})..."
    kill "${d#/proc/}" 2>/dev/null || true
  fi
done

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$BACKEND_PORT") 2>/dev/null; }
port_pids() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -ti tcp:"$BACKEND_PORT" 2>/dev/null || true
  elif command -v fuser >/dev/null 2>&1; then
    fuser "$BACKEND_PORT"/tcp 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' || true
  else
    ss -tlnp 2>/dev/null | grep "[:.]$BACKEND_PORT " | grep -oP 'pid=\K[0-9]+' | sort -u || true
  fi
}
if port_busy; then
  for p in $(port_pids); do
    # Only kill node processes — never an unrelated service on the same port
    if [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "node" ]; then
      echo "[clean] Killing stale backend (PID $p)..."
      kill "$p" 2>/dev/null || true
    fi
  done
  for _ in 1 2 3 4 5; do port_busy || break; sleep 1; done
  for p in $(port_pids); do
    [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "node" ] && kill -9 "$p" 2>/dev/null || true
  done
  sleep 1
  if port_busy; then
    echo "ERROR: Port $BACKEND_PORT is occupied by another process — free it and retry."
    exit 1
  fi
fi

# ── 2. Start backend ──────────────────────────────────────────────────
echo "[1/3] Starting Node.js backend..."
cd "$BACKEND_DIR"

if [ -n "${REDTEAM_CSCAN_ENV_FILE:-}" ]; then
  echo "[CScan] Checking connection and credentials..."
  if ! "$NODE_BIN" scripts/check-source-environment.js --api; then
    echo "[CScan] Connection unavailable. Saved reports remain viewable; remote collection requires a working tunnel and credentials."
  fi
fi

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
