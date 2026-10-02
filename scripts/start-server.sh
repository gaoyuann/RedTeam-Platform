#!/usr/bin/env bash
# RedTeam Platform - Server start script
# Runs on the x86 server (便携式 AI 算力主站)
# Starts: Node.js backend + SQLite + container engine
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# ── Configuration ──────────────────────────────────────────────────────
BACKEND_DIR="${BACKEND_DIR:-$BASE_DIR/backend}"
DATA_DIR="${REDTEAM_DATA_DIR:-$BASE_DIR/data}"
PORT="${PORT:-3002}"
HOST="${HOST:-0.0.0.0}"
MAX_WAIT=30

echo "=== RedTeam Platform Server ==="
echo "Host: $HOST:$PORT"
echo "Data: $DATA_DIR"

# ── Check container engine ─────────────────────────────────────────────
ENGINE=""
if command -v podman &>/dev/null; then
  ENGINE="podman"
elif command -v docker &>/dev/null; then
  ENGINE="docker"
fi
echo "Container engine: ${ENGINE:-none (host mode)}"

# ── JWT Secret warning ─────────────────────────────────────────────────
if [ -z "${JWT_SECRET:-}" ]; then
  echo "WARNING: JWT_SECRET not set. Using insecure default. Set JWT_SECRET env var in production!"
fi

# ── Kill stale backend still holding the port (skipped trap on SIGKILL) ─
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }
port_pids() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -ti tcp:"$PORT" 2>/dev/null || true
  elif command -v fuser >/dev/null 2>&1; then
    fuser "$PORT"/tcp 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' || true
  else
    ss -tlnp 2>/dev/null | grep "[:.]$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u || true
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
    echo "ERROR: Port $PORT is occupied by another process — free it and retry."
    exit 1
  fi
fi

# ── Start backend ──────────────────────────────────────────────────────
echo "[1/1] Starting Node.js backend..."
cd "$BACKEND_DIR"

export REDTEAM_DATA_DIR="$DATA_DIR"
export HOST="$HOST"
export PORT="$PORT"

node src/server.js &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID (node: $(node --version 2>/dev/null || echo 'unknown'))"

# Ensure backend is killed on exit
trap 'echo "Stopping backend (PID $BACKEND_PID)..."; kill $BACKEND_PID 2>/dev/null || true; wait $BACKEND_PID 2>/dev/null || true' EXIT HUP INT TERM

# ── Wait for health ────────────────────────────────────────────────────
echo "Waiting for backend..."
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  if curl -sf "http://127.0.0.1:${PORT}/api/health" > /dev/null 2>&1; then
    echo "Backend ready after ${WAITED}s"
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

echo ""
echo "Server running at http://${HOST}:${PORT}"
echo "Clients can connect from cloud laptops via this address."
echo "Press Ctrl+C to stop"

# Wait forever
wait $BACKEND_PID
