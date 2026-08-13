#!/usr/bin/env bash
# update-client.sh — 云笔电上一键更新前端
# 用法: bash update-client.sh
# 效果: git pull → 增量编译 → 重启前端
set -euo pipefail

PROJECT_DIR="$HOME/RedTeam-Platform"
SERVER_ADDR="${REDTEAM_SERVER:-192.168.1.103:3002}"
BRANCH="main"

cd "$PROJECT_DIR"

echo "=== 更新前端 ==="

# ── 1. 拉取最新代码 ────────────────────────────────────────────────────
echo "[1/3] 拉取代码..."
git pull origin "$BRANCH" 2>&1 || echo "  拉取失败，使用本地代码继续"

# ── 2. 增量编译 ────────────────────────────────────────────────────────
echo "[2/3] 编译..."
if [ ! -d build/CMakeFiles ]; then
  cmake -B build -S .
fi
cmake --build build -j$(nproc 2>/dev/null || echo 1)

# ── 3. 重启前端 ────────────────────────────────────────────────────────
echo "[3/3] 重启前端..."
pkill -f 'RedTeam-Platform' 2>/dev/null || true
sleep 0.5

nohup ./build/frontend/RedTeam-Platform --server "$SERVER_ADDR" \
  > /tmp/redteam-frontend.log 2>&1 &
echo "前端已启动 (PID: $!)，连接服务器: $SERVER_ADDR"
echo "=== 更新完成 ==="
