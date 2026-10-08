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
SYNC_SOURCE="${REDTEAM_SYNC_SOURCE:-}"
BUILD_JOBS="${BUILD_JOBS:-2}"
UPDATE_ONCE="${UPDATE_ONCE:-0}"
STATE_DIR="$PROJECT_DIR/.client-update"

cd "$PROJECT_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

trust_client_binary() {
  local policy_tool
  policy_tool=$(command -v kysec_set) || return 0
  sudo -n "$policy_tool" -n exectl -v verified "$1" >>"$LOG" 2>&1
}

restart_synced_client() {
  local client_pid
  if systemctl --user is-active --quiet redteam-client.service; then
    systemctl --user restart redteam-client.service || return 1
  else
    pkill -f "^$PROJECT_DIR/build/frontend/RedTeam-Platform([[:space:]]|$)" 2>/dev/null || true
    systemd-run --user --unit=redteam-client --collect \
      --property=Type=exec --property=Restart=on-failure \
      --setenv="DISPLAY=${DISPLAY:-:0}" \
      --setenv="XAUTHORITY=${XAUTHORITY:-$HOME/.Xauthority}" \
      --setenv="REDTEAM_SERVER=${REDTEAM_SERVER:-192.168.1.103:3002}" \
      "$SCRIPT_DIR/start-app.sh" >>"$LOG" 2>&1 || return 1
  fi
  sleep 2
  systemctl --user is-active --quiet redteam-client.service || return 1
  client_pid=$(systemctl --user show redteam-client.service --property=MainPID --value) || return 1
  [ "$(readlink "/proc/$client_pid/exe")" = "$PROJECT_DIR/build/frontend/RedTeam-Platform" ]
}

sync_client_source() {
  mkdir -p "$STATE_DIR/source" || return 1
  local changes
  if ! changes=$(rsync -azci --delete \
    --include='/CMakeLists.txt' --include='/frontend/***' \
    --include='/third_party/' --include='/third_party/rockey/***' \
    --exclude='*' \
    -e "${RSYNC_RSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes}" \
    "${SYNC_SOURCE%/}/" "$STATE_DIR/source/" 2>>"$LOG"); then
    touch "$STATE_DIR/pending"
    log "ERROR: 源码同步失败，保留当前客户端"
    return 1
  fi
  if [ -n "$changes" ]; then
    printf '%s\n' "$changes" >>"$LOG"
    touch "$STATE_DIR/pending"
  fi
  if [ ! -f "$STATE_DIR/pending" ] && [ -f "$STATE_DIR/deployed" ]; then
    return 0
  fi

  log "服务器源码已同步，开始独立构建 (jobs=$BUILD_JOBS)"
  if ! cmake -B "$STATE_DIR/build" -S "$STATE_DIR/source" >>"$LOG" 2>&1 || \
     ! cmake --build "$STATE_DIR/build" -j"$BUILD_JOBS" >>"$LOG" 2>&1; then
    log "ERROR: 编译失败，保留当前客户端，下轮重试"
    return 1
  fi

  local live_binary="$PROJECT_DIR/build/frontend/RedTeam-Platform"
  local built_binary="$STATE_DIR/build/frontend/RedTeam-Platform"
  if [ ! -x "$built_binary" ]; then
    log "ERROR: 构建未生成可执行客户端"
    return 1
  fi
  mkdir -p "$(dirname "$live_binary")" || return 1
  if [ -f "$live_binary" ]; then
    cp -p "$live_binary" "$STATE_DIR/RedTeam-Platform.previous" || return 1
  fi
  if [ -d "$STATE_DIR/build/frontend/third_party" ]; then
    cp -a "$STATE_DIR/build/frontend/third_party" "$(dirname "$live_binary")/" || return 1
  fi
  install -m 755 "$built_binary" "$live_binary.next" || return 1
  if ! trust_client_binary "$live_binary.next"; then
    log "ERROR: 新客户端未获单文件执行授权，保留当前客户端"
    return 1
  fi
  mv -f "$live_binary.next" "$live_binary" || return 1
  if ! trust_client_binary "$live_binary"; then
    log "ERROR: 最终客户端未获单文件执行授权，回退到上一版"
    if [ -f "$STATE_DIR/RedTeam-Platform.previous" ]; then
      install -m 755 "$STATE_DIR/RedTeam-Platform.previous" "$live_binary.next" && \
        trust_client_binary "$live_binary.next" && \
        mv -f "$live_binary.next" "$live_binary" && \
        trust_client_binary "$live_binary" && restart_synced_client
    fi
    return 1
  fi
  if ! restart_synced_client; then
    log "ERROR: 客户端启动失败，回退到上一版"
    if [ -f "$STATE_DIR/RedTeam-Platform.previous" ]; then
      install -m 755 "$STATE_DIR/RedTeam-Platform.previous" "$live_binary.next" && \
        trust_client_binary "$live_binary.next" && \
        mv -f "$live_binary.next" "$live_binary" && \
        trust_client_binary "$live_binary" && restart_synced_client
    fi
    return 1
  fi
  rm -f "$STATE_DIR/pending"
  date -Is > "$STATE_DIR/deployed"
  log "源码同步、ARM64 构建及客户端切换完成"
}

log "=== auto-update daemon started (branch=$BRANCH, interval=${POLL_INTERVAL}s) ==="

while true; do
  if [ -n "$SYNC_SOURCE" ]; then
    sync_client_source
    update_status=$?
    if [ "$UPDATE_ONCE" = 1 ]; then
      exit "$update_status"
    fi
    sleep "$POLL_INTERVAL"
    continue
  fi
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
