#!/usr/bin/env bash
# RedTeam Platform - One-click start script
# Starts Node.js backend, waits for health, then launches Qt frontend
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_BIN="$PROJECT_ROOT/build/frontend/RedTeam-Platform"
HEALTH_URL="http://127.0.0.1:3002/api/health"
MAX_WAIT=30  # seconds

echo "=== RedTeam Platform Start ==="

# ── 1. Start backend ─────────────────────────────────────────────────────
echo "[1/3] Starting Node.js backend..."
cd "$BACKEND_DIR"
node src/server.js &
BACKEND_PID=$!
echo "       Backend PID: $BACKEND_PID"

# ── 2. Wait for backend health ──────────────────────────────────────────
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

# ── 3. Start Qt frontend ────────────────────────────────────────────────
echo "[3/3] Starting Qt frontend..."
if [ -x "$FRONTEND_BIN" ]; then
  "$FRONTEND_BIN"
  EXIT_CODE=$?
else
  echo "ERROR: Frontend binary not found at $FRONTEND_BIN"
  echo "       Run: cmake -B build -S . && cmake --build build"
  EXIT_CODE=1
fi

# ── Cleanup ─────────────────────────────────────────────────────────────
echo "Stopping backend (PID $BACKEND_PID)..."
kill $BACKEND_PID 2>/dev/null || true
exit $EXIT_CODE
