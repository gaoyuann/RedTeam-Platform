#!/usr/bin/env bash
# install-desktop.sh — 在云笔电上安装桌面图标 + 应用菜单项
# 用法: bash scripts/install-desktop.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="redteam-platform"
ICON_SRC="$PROJECT_DIR/frontend/resources/app-icon.png"

if [ ! -f "$ICON_SRC" ]; then
  echo "错误: 找不到图标 $ICON_SRC" >&2
  exit 1
fi

# ── 1. 安装图标到 hicolor 主题 ─────────────────────────────────────────
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
mkdir -p "$ICON_DIR"
cp "$ICON_SRC" "$ICON_DIR/$APP_NAME.png"
echo "[1/3] 图标 → $ICON_DIR/$APP_NAME.png"

# ── 2. 生成 .desktop 文件 ─────────────────────────────────────────────
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"
cat > "$APPS_DIR/$APP_NAME.desktop" << EOF
[Desktop Entry]
Type=Application
Name=RedTeam 智能渗透测试平台
Comment=AI 驱动自动化渗透测试系统
Exec=$SCRIPT_DIR/start-app.sh
Icon=$APP_NAME
Terminal=false
Categories=Development;Security;
StartupWMClass=RedTeam-Platform
EOF
echo "[2/3] 桌面项 → $APPS_DIR/$APP_NAME.desktop"

# ── 3. 桌面快捷方式 ───────────────────────────────────────────────────
DESKTOP_DIR="$HOME/Desktop"
if [ -d "$DESKTOP_DIR" ]; then
  cp "$APPS_DIR/$APP_NAME.desktop" "$DESKTOP_DIR/"
  chmod +x "$DESKTOP_DIR/$APP_NAME.desktop"
  echo "[3/3] 桌面快捷方式 → $DESKTOP_DIR/$APP_NAME.desktop"
else
  echo "[3/3] 跳过桌面快捷方式（$DESKTOP_DIR 不存在，仅装到应用菜单）"
fi

# 刷新桌面数据库（让菜单立刻出现）
update-desktop-database "$APPS_DIR" 2>/dev/null || true

echo ""
echo "=== 安装完成 ==="
echo "应用菜单中应出现「RedTeam 智能渗透测试平台」，点击即可启动"
echo "若菜单未刷新，注销重登录或运行: update-desktop-database $APPS_DIR"
