#!/usr/bin/env bash
# deploy-client.sh — 一键部署前端到云笔电
# 用法: ./scripts/deploy-client.sh <云笔电IP> [服务器IP:端口]
# 示例: ./scripts/deploy-client.sh 192.168.1.200 192.168.1.100:3002
set -euo pipefail

REMOTE_HOST="${1:?用法: $0 <云笔电IP> [服务器IP:端口]}"
SERVER_ADDR="${2:-}"  # 可选，前端连接的远程服务器地址

REMOTE_DIR="/opt/RedTeam-Platform"  # 云笔电上的项目目录
REMOTE_USER="${REMOTE_USER:-root}"  # SSH 用户，可通过环境变量覆盖

echo "=== 部署前端到 ${REMOTE_USER}@${REMOTE_HOST} ==="

# ── 1. 同步源码（只传变化的文件，很快） ──────────────────────────────
echo "[1/3] 同步源码..."
rsync -az --delete \
  --exclude='build/' \
  --exclude='.git/' \
  --exclude='node_modules/' \
  --exclude='data/*.db' \
  --exclude='*.tar' \
  --exclude='backend/' \
  ./ "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/frontend-sync/"

# ── 2. 远程增量编译 ──────────────────────────────────────────────────
echo "[2/3] 远程编译..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" bash -s <<REMOTE_SCRIPT
set -e
cd ${REMOTE_DIR}/frontend-sync

# 首次需要 cmake 配置
if [ ! -d build ]; then
  echo "  首次编译，执行 cmake 配置..."
  cmake -B build -S .
fi

# 增量编译（只重编译变化的文件）
cmake --build build -j\$(nproc)
REMOTE_SCRIPT

# ── 3. 重启前端 ──────────────────────────────────────────────────────
echo "[3/3] 重启前端..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" bash -s <<REMOTE_SCRIPT2
set -e

# 杀掉旧的前端进程
pkill -f 'RedTeam-Platform' 2>/dev/null || true
sleep 0.5

# 启动新的前端
cd ${REMOTE_DIR}/frontend-sync
if [ -n "${SERVER_ADDR}" ]; then
  echo "  启动前端，连接服务器: ${SERVER_ADDR}"
  nohup ./build/frontend/RedTeam-Platform --server ${SERVER_ADDR} > /tmp/redteam-frontend.log 2>&1 &
else
  echo "  启动前端（默认连接 127.0.0.1:3002）"
  nohup ./build/frontend/RedTeam-Platform > /tmp/redteam-frontend.log 2>&1 &
fi

echo "  前端已启动 (PID: \$!)"
REMOTE_SCRIPT2

echo "=== 部署完成 ==="
