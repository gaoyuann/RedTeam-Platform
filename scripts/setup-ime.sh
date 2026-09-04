#!/usr/bin/env bash
# setup-ime.sh — Install Chinese input method (fcitx5) for Qt5 on Ubuntu/Debian
# Usage: sudo bash scripts/setup-ime.sh
set -euo pipefail

echo "=== RedTeam Platform — Chinese IME Setup ==="
echo ""

# ── 1. Install fcitx5 + Chinese addons + Qt5 integration ──────────────
echo "[1/3] Installing fcitx5, Chinese addons, and Qt5 plugin..."
apt update
apt install -y \
  fcitx5 \
  fcitx5-chinese-addons \
  fcitx5-frontend-qt5 \
  fcitx5-config-qt

echo ""
echo "[2/3] Configuring environment variables..."

# ── 2. Write env vars to ~/.bashrc (idempotent) ───────────────────────
BASHRC="${SUDO_USER_HOME:-$HOME}/.bashrc"
if [ -n "${SUDO_USER:-}" ] && [ -z "${SUDO_USER_HOME:-}" ]; then
  BASHRC="/home/$SUDO_USER/.bashrc"
fi

MARKER="# >>> redteam-ime >>>"
END_MARKER="# <<< redteam-ime <<<"

# Remove old block if exists
if grep -qF "$MARKER" "$BASHRC" 2>/dev/null; then
  sed -i "/$MARKER/,/$END_MARKER/d" "$BASHRC"
fi

cat >> "$BASHRC" << 'ENVEOF'
# >>> redteam-ime >>>
export QT_IM_MODULE=fcitx
export GTK_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx
# <<< redteam-ime <<<
ENVEOF

echo "  Added to $BASHRC:"
echo "    QT_IM_MODULE=fcitx"
echo "    GTK_IM_MODULE=fcitx"
echo "    XMODIFIERS=@im=fcitx"

echo ""
echo "[3/3] Done!"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  安装完成！请执行以下步骤："
echo ""
echo "  1. 重新打开终端（使环境变量生效）"
echo "  2. 启动 fcitx5："
echo "       fcitx5 -d"
echo "  3. 配置输入法（添加拼音/五笔）："
echo "       fcitx5-configtool"
echo "  4. 启动 RedTeam Platform，即可使用中文输入"
echo ""
echo "  提示：fcitx5 -d 可加入 ~/.bashrc 或 start.sh 实现自动启动"
echo "══════════════════════════════════════════════════════════════"
