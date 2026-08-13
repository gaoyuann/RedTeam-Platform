#!/usr/bin/env bash
# ============================================================
# RedTeam Platform — 后端服务器环境一键安装脚本
# 目标系统: Ubuntu 22.04 (x86_64)
# 用途: 服务器端 (Node.js 后端 + Docker + 数据库)
# ============================================================
set -euo pipefail

# 颜色输出
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ── 0. 前置检查 ──────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
  err "请用 sudo 运行此脚本: sudo bash scripts/setup-server.sh"
  exit 1
fi

info "=== RedTeam 后端服务器环境安装 ==="
info "系统: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
info "内核: $(uname -r)"
info "架构: $(uname -m)"
echo ""

# ── 1. 系统基础更新 + 编译工具链 ────────────────────────────
info "[1/4] 更新系统 & 安装编译工具链 (gcc/g++/make/cmake/python3)..."
apt update && apt upgrade -y
apt install -y \
    build-essential \
    gcc g++ \
    cmake \
    make \
    pkg-config \
    python3 python3-pip python3-dev \
    curl wget \
    ca-certificates \
    gnupg \
    lsb-release \
    unzip \
    net-tools
info "[1/4] ✓ 编译工具链安装完成"

# ── 2. Node.js 20 LTS ───────────────────────────────────────
info "[2/4] 安装 Node.js 20 LTS..."
if command -v node &>/dev/null && [[ "$(node -v | cut -d'v' -f2 | cut -d'.' -f1)" -ge 18 ]]; then
  info "Node.js $(node -v) 已安装，跳过"
else
  # NodeSource 官方源
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt install -y nodejs
fi
info "  Node.js: $(node -v)"
info "  npm:     $(npm -v)"
info "[2/4] ✓ Node.js 安装完成"

# ── 3. Docker Engine ────────────────────────────────────────
info "[3/4] 安装 Docker Engine..."
if command -v docker &>/dev/null; then
  info "Docker $(docker --version) 已安装，跳过"
else
  # 添加 Docker 官方 GPG key 和仓库
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  apt update
  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  # 启动 Docker & 开机自启
  systemctl enable --now docker

  # 将当前非 root 用户加入 docker 组（免 sudo docker）
  SUDO_USER="${SUDO_USER:-$(whoami)}"
  if [[ "$SUDO_USER" != "root" ]]; then
    usermod -aG docker "$SUDO_USER"
    warn "已将用户 '$SUDO_USER' 加入 docker 组，需重新登录后生效"
  fi
fi
info "  Docker: $(docker --version 2>/dev/null || echo '启动中...')"
info "[3/4] ✓ Docker 安装完成"

# ── 4. 后端 npm 依赖 ───────────────────────────────────────
info "[4/4] 安装后端 npm 依赖..."
BACKEND_DIR="$(cd "$(dirname "$0")/.." && pwd)/backend"
if [[ -f "$BACKEND_DIR/package.json" ]]; then
  cd "$BACKEND_DIR"
  npm install
  info "  npm 依赖安装完成 ($(ls node_modules | wc -l) 个包)"
else
  warn "未找到 $BACKEND_DIR/package.json，跳过 npm install"
  warn "部署项目后请手动执行: cd backend && npm install"
fi
info "[4/4] ✓ npm 依赖安装完成"

# ── 安装结果汇总 ────────────────────────────────────────────
echo ""
info "========================================="
info "  安装完成！环境汇总："
info "========================================="
echo ""
info "  Node.js:    $(node -v)"
info "  npm:        $(npm -v)"
info "  GCC:        $(gcc -dumpversion)"
info "  CMake:      $(cmake --version | head -1)"
info "  Python:     $(python3 --version)"
info "  Docker:     $(docker --version 2>/dev/null || echo '未安装')"
echo ""
warn "待办事项："
warn "  1. [必须] 重新登录 SSH 使 docker 组权限生效"
warn "  2. [可选] 如需本地 LLM 推理，安装 Ollama: curl -fsSL https://ollama.com/install.sh | sh"
warn "  3. [可选] 如需用 Podman 替代 Docker: apt install podman"
echo ""
info "启动后端: cd backend && npm run dev"
info "健康检查: curl http://localhost:3002/api/health"
