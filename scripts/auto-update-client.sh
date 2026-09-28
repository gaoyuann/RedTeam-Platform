#!/usr/bin/env bash
# auto-update-client.sh — 云笔电客户端自动更新守护
# 每 30 秒轮询 git 远程，有新提交就 pull → 增量编译 → 重启前端
# 由 systemd --user 服务 redteam-autoupdate.service 托管
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BRANCH="${BRANCH:-main}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"
LOG="$PROJECT_DIR/update.log"

cd "$PROJECT_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

log "=== auto-update daemon started (branch=$BRANCH, interval=${POLL_INTERVAL}s) ==="

while true; do
  # fetch 远程（不 merge），失败则等待重试
  if ! git fetch origin "$BRANCH" >>"$LOG" 2>&1; then
    log "WARNING: git fetch 失败，${POLL_INTERVAL}s 后重试"
    sleep "$POLL_INTERVAL"
    continue
  fi

  LOCAL=$(git rev-parse HEAD 2>/dev/null || echo "")
  REMOTE=$(git rev-parse "origin/$BRANCH" 2>/dev/null || echo "")

  if [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
    log "检测到更新: $LOCAL → $REMOTE"

    # 1. 拉取代码
    if git pull origin "$BRANCH" >>"$LOG" 2>&1; then
      log "git pull 成功"

      # 2. 增量编译（旧前端继续运行，编译不中断用户）
      if cmake --build build -j"$(nproc 2>/dev/null || echo 2)" >>"$LOG" 2>&1; then
        log "编译成功，重启前端"

        # 3. 重启前端
        pkill -f 'build/frontend/RedTeam-Platform' 2>/dev/null || true
        sleep 1
        nohup "$SCRIPT_DIR/start-app.sh" >>"$LOG" 2>&1 &
        log "前端已重启 (PID $!)"
      else
        log "ERROR: 编译失败，保留旧前端继续运行"
      fi
    else
      log "ERROR: git pull 失败，跳过本次更新"
    fi
  fi

  sleep "$POLL_INTERVAL"
done
