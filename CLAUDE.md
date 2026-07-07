# RedTeam-Platform — 信息系统渗透智能化测试平台

## 项目背景

本项目是对 [RedTeam-Edu](../RedTeam-Edu/)（React+Electron+Node.js）的**全面重构**，按照老师要求：

1. **前端改用 Qt5/C++**（兼容银河麒麟/统信UOS等国产操作系统）
2. **引入数据库**（当前系统无数据库，全靠 JSON/内存）
3. **工具容器化**（Podman/Docker，支持离线物理迁移）
4. **工作流改造**：先扫描 → 展示结果 → 智能生成 Playbook → 再执行（当前是直接选 Playbook 执行）

## 架构

```
Qt5/C++ 前端 (AppImage 分发)
    ↕ HTTP (127.0.0.1:3002)
Node.js 后端 (内嵌运行时，本地服务，从 RedTeam-Edu 复用)
    ↕
SQLite 数据库 + Podman/Docker 容器化工具
```

- **前端**：Qt 5.15.3 + CMake + C++17
- **后端**：复用现有 Node.js 后端，内嵌 Node 运行时，绑定 localhost
- **数据库**：SQLite（单文件，随软件分发）
- **工具执行**：Podman/Docker 容器化，镜像离线打包
- **分发**：AppImage / deb / rpm，单目录包含所有组件，start.sh 一键启动

## 当前状态

**Phase 0 已完成**：项目骨架搭建，Qt5 空壳窗口编译运行通过。

- 7 个一级模块导航栏（占位页面）
- 后端连接检测按钮（QNetworkAccessManager → 127.0.0.1:3002）
- 初始 git commit: `b0c919d`

## 功能模块（7个一级 / 28个二级）

| # | 一级模块 | 二级子功能数 | 状态 |
|---|---------|------------|------|
| 1 | 渗透测试资源部署配置 | 5 | ✅ 已实现 |
| 2 | 漏洞利用想定与预案 | 3 | ✅ 已实现 |
| 3 | 网络拓扑探测与绘制 | 4 | ❌ 未实现 |
| 4 | 脆弱性扫描 | 4 | ✅ 已实现 |
| 5 | 漏洞攻击测试 | 3 | ⚠️ 部分实现 |
| 6 | 测试评估 | 2 | ⚠️ 部分实现 |
| 7 | 系统管理 | 7 | ⚠️ 部分实现 |

## 下一步计划

| Phase | 内容 | 状态 |
|-------|------|------|
| 0 | 技术验证脚手架 | ✅ 完成 |
| 1 | 数据库设计与核心数据迁移 | ⬜ 待开始 |
| 2 | 工具容器化 | ⬜ 待开始 |
| 3 | Qt 前端主框架 + 已实现模块迁移 | ⬜ 待开始 |
| 4 | 扫描驱动工作流改造 | ⬜ 待开始 |
| 5 | 未实现模块前端壳 | ⬜ 待开始 |
| 6 | 打包分发与国产化适配 | ⬜ 待开始 |

**下一步**：Phase 1（数据库设计）和 Phase 2（工具容器化）可并行推进。

## 项目结构

```
RedTeam-Platform/
├── CMakeLists.txt
├── frontend/               # Qt5 C++ 前端
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.cpp
│   │   ├── MainWindow.h
│   │   └── MainWindow.cpp
│   └── resources/
├── backend/                # Node.js 后端（Phase 3 从 RedTeam-Edu 迁入）
├── containers/             # 工具容器镜像 Dockerfile（Phase 2）
├── data/                   # SQLite 数据库 + 知识图谱 + Playbook（Phase 1）
├── scripts/                # 打包/分发脚本（Phase 6）
└── docs/                   # 项目文档
    └── 系统重构需求与功能模块分析.md  # 完整规划文档
```

## 开发环境

- WSL2 Ubuntu 22.04 on Windows 11
- Qt 5.15.3 (apt), CMake 3.22.1, g++ 11.4.0
- 构建命令：`cmake -B build -S . && cmake --build build`
- 运行：`./build/frontend/RedTeam-Platform`

## 关键参考

- 完整规划文档：`docs/系统重构需求与功能模块分析.md`
- 原项目（后端复用来源）：`/home/gaoyuan/RedTeam-Edu/`
