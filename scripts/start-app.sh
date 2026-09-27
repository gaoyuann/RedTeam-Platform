#!/usr/bin/env bash
# RedTeam Platform — 桌面启动入口（云笔电）
# 桌面 .desktop 图标和自动更新重启都调此脚本，保证启动方式一致
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER="${REDTEAM_SERVER:-192.168.1.103:3002}"
BIN="$PROJECT_DIR/build/frontend/RedTeam-Platform"

if [ ! -x "$BIN" ]; then
  echo "错误: 找不到前端程序 $BIN" >&2
  exit 1
fi

# 确保 DISPLAY（从 systemd 或 SSH 启动时可能缺）
export DISPLAY="${DISPLAY:-:0}"

# 输入法检测（复用 start.sh 逻辑，银河麒麟常用 fcitx5/ibus）
if [ -z "${QT_IM_MODULE:-}" ]; then
  if pgrep -x fcitx5 >/dev/null 2>&1; then
    export QT_IM_MODULE=fcitx GTK_IM_MODULE=fcitx XMODIFIERS=@im=fcitx
  elif pgrep -x fcitx >/dev/null 2>&1; then
    export QT_IM_MODULE=fcitx GTK_IM_MODULE=fcitx XMODIFIERS=@im=fcitx
  elif pgrep -x ibus-daemon >/dev/null 2>&1; then
    export QT_IM_MODULE=ibus GTK_IM_MODULE=ibus XMODIFIERS=@im=ibus
  fi
fi

echo "启动 RedTeam Platform，连接服务器: $SERVER"
exec "$BIN" --server "$SERVER"
