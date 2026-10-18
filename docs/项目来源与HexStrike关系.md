# 项目来源与 HexStrike-AI 的关系

更新日期：2026-10-16。本文用于项目介绍、汇报和后续文档编写，说明开发来源与当前实现的区别。

## 可直接使用的项目介绍

> RedTeam-Platform 基于 HexStrike-AI 开展二次开发，经过模块移植、执行架构调整和业务能力扩展，逐步形成当前的平台。平台采用 Qt 桌面前端、Node.js 后端与 SQLite 存储，将目标配置、扫描分析、测试预案、受控执行、证据整理和报告输出组织成工作流。现有主执行链由平台自身实现，同时保留了早期项目的部分能力与设计。

项目与 HexStrike-AI 的关系应表述为“基于上游二次开发并持续演进”。当前能够独立组织工具执行，不改变项目的开发来源；也不宜仅概括为“模仿 HexStrike”或“完全从零自研”。

## HexStrike 是服务框架，MCP 是协议

HexStrike-AI 是将安全工具封装为可调用能力的软件框架／工具服务，MCP 是其采用的通信协议。上游典型链路是：

```text
用户目标 → 外部 AI Agent → MCP 工具接口（hexstrike_mcp.py）
         → HTTP 服务（hexstrike_server.py）→ 底层安全工具
         → 执行结果返回 Agent → 分析并决定下一步
```

AI Agent 负责理解目标与分析结果，HexStrike 组织工具调用，底层工具完成具体检测或验证。部署服务本身不等于完成自主测试闭环。上游实现参考：[MCP 适配器](https://github.com/0x4m4/hexstrike-ai/blob/master/hexstrike_mcp.py)、[执行服务](https://github.com/0x4m4/hexstrike-ai/blob/master/hexstrike_server.py)。链接指向上游分支，后续集成时需固定并核验版本。

## 当前关系与证据边界

| 维度 | 当前说明 | 依据与限制 |
| --- | --- | --- |
| 开发来源 | 项目从 HexStrike-AI 出发，逐步修改形成当前版本 | 项目开发者在 2026-10-16 讨论中确认；尚未完成逐模块上游代码与提交历史比对 |
| 中间阶段继承 | 当前模块保留 RedTeam-Edu／hexstrike-edu 移植标记，部分仍在主链中使用 | 源码可核对；旧目录名不能单独证明每个模块都来自官方上游 |
| 当前运行依赖 | 已检查的主执行链直接调用本项目引擎与工具执行器，未发现必须经过独立 HexStrike 服务的调用 | 本地源码核对，不代表已核验远端部署状态 |
| 能力演进 | 当前存在 Qt 界面、Node.js 执行链、任务与审批、证据报告、源码关联验证等实现 | 可以介绍当前能力；哪些是相对上游新增、哪些构成技术创新，仍需逐项比较 |

当前主要执行链为：

```text
Qt 前端 → 本项目任务／预案接口 → executionEngine
       → 按执行模式调用 ReAct 或专用程序测试决策
       → toolRunner／内置请求处理 → 容器或宿主机工具
       → 本项目证据记录、状态汇总与报告
```

关键代码依据：

- [executionEngine](../backend/src/services/executionEngine.js)：组织执行，调用规则解析和 ReAct 防护模块。
- [toolRunner](../backend/src/tools/toolRunner.js)：直接调度容器、宿主机工具及内置请求处理。
- [rulesEngine](../backend/src/services/rulesEngine.js)、[parsers](../backend/src/services/parsers.js)、[specLoader](../backend/src/services/specLoader.js)、[reactRuntimeGuard](../backend/src/services/reactRuntimeGuard.js)、[playbookAiChat](../backend/src/services/playbookAiChat.js)：保留旧项目移植说明。
- [预案导入迁移](../backend/src/db/migrations/003_import_playbooks.js)：优先使用本仓库预案，保留旧项目路径回退；属于历史兼容，不是运行时调用 HexStrike 服务。

当前载荷加载路径是本地 `payloader_data.json` 和已入库的 AI 生成记录；[payloadGenerator](../backend/src/services/payloadGenerator.js) 直接调用本项目模型客户端。新生成记录通过结构校验后自动入库，旧候选记录仍可由管理员处理。因此不能把所有载荷统称为“HexStrike 生成”，也不能把生成结构化参数等同于已验证利用成功。静态载荷与知识数据的完整来源需单独追溯，项目来源不能替代数据来源证明。

## 汇报与后续接入的表述

- 介绍来源时说明“基于 HexStrike-AI 二次开发”，介绍当前实现时说明“主执行链由平台自身实现”。
- 当前工程成果可以围绕任务组织、受控执行、证据追溯和源码验证展开；不将第三方工具算法或模型能力计为本项目原创。
- 未进行受控对比前，不声称相较 HexStrike 提升了准确率、效率或利用成功率。
- “再次引入 HexStrike”指将上游服务重新接入当前架构。可评估其作为可选工具执行后端的价值，保留本项目任务、审批、证据和报告职责；这只是架构建议，尚未实施或验证收益。

本文依据开发者确认、当前本地源码与上游公开源码整理，未启动服务、执行扫描或核验远端环境。
