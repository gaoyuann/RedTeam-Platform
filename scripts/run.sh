#!/usr/bin/env bash
# RedTeam Platform 一键启动脚本（云笔电客户端）
# 用法: ./run.sh [服务器IP:端口]
# 示例: ./run.sh 192.168.1.103:3002
#       ./run.sh              # 使用默认 192.168.1.103:3002

SERVER="${1:-192.168.1.103:3002}"
BIN="$HOME/RedTeam-Platform/build/frontend/RedTeam-Platform"

if [ ! -x "$BIN" ]; then
  echo "错误: 找不到前端程序 $BIN"
  exit 1
fi

echo "连接服务器: $SERVER"
exec "$BIN" --server "$SERVER"
