# 源码扫描结果呈现

详情页沿用 pentagi-v3 的 `src/ui/pages/source_scan/SourceScanPage.cpp` 交互：左侧文件树、中间只读源码、右侧全部发现及详情。代码编辑器的行号栏和 C/C++ 高亮复用原版实现，Qt 技术栈不变。任务提交仍使用本项目的远端源码 URL 接口。

## 数据与联动

- 文件树主要来自任务接口的 `source_files` 快照元数据，文件总数只统计快照。
- `/work/src/` 是远端快照根目录；仅去掉这个明确前缀后与报告相对路径匹配，任务 ID 始终参与键值。其他绝对路径不会按 basename 猜测匹配。
- 报告引用但没有快照的文件置于“待核对 · 未匹配源码”，不生成虚构代码。
- 选择文件只切换代码，不缩小右侧发现列表。严重度筛选作用于整个任务。
- 点击发现选择对应文件，调用已有只读 source-file 接口加载内容并核对 SHA-256 元数据，定位和高亮行范围。未匹配或越界位置明确标注待核对。
- 刷新保留所选发现。异步源码请求通过序号和文件键防止旧响应覆盖新选择。
- 原始报告与依据放在右侧标签页，代码区保持固定；报告预览上限 64000 字符并显示截断提示。
- 扫描发现仍是待复核记录；浏览页面不会创建或执行验证任务。原有显式测试准备入口保留。

## 验证

```sh
cmake --build build --target PentagiSourceHostChecks RedTeam-SourceScanDetailChecks -j2
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 build/frontend/RedTeam-SourceScanDetailChecks
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1.5 build/frontend/RedTeam-SourceScanDetailChecks
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=2 build/frontend/RedTeam-SourceScanDetailChecks
QT_QPA_PLATFORM=offscreen build/frontend/PentagiSourceHostChecks
```

单元/交互检查使用确定性接口样例；真实结果截图另通过现有后端只读接口加载 Flow15 已保存结果。截图使用修改后的 Qt 组件离屏渲染，不代表已发布或已部署新前端。


## 逐漏洞测试界面
- 保留任务主流程；逐漏洞窗口分为“漏洞与测试”“载荷代码”“测试结果与历史”。
- 不再使用“草稿”作为界面状态；手工编辑放在“修改测试参数”，仍需显式保存。
- 载荷库与手工步骤关联折叠在“高级设置：方案与载荷”中，仍需显式绑定；源码载荷收集、失败重试与 Python 改写也可从该入口展开。
- 源码发现可在没有测试方案时整理原 Flow 载荷，再生成所选片段的 Python 版本。
  这不是从零生成任意漏洞载荷：原 Flow 没有可核实片段时可返回空结果。
- 代码生成、准备方案与执行相互独立；Python/C/C++ 本地隔离执行及其结论边界见 [载荷与本地验证执行](source-code-execution.md)。

源码任务页仅展示提交表单与任务列表，不内嵌详情。双击任务或使用打开详情按钮弹出三栏详情；历史扫描入口也使用同一详情组件。刷新列表不会自动弹窗。

## 自动载荷收集

关联任务的源码扫描进入 COMPLETED/PARTIAL 并保存发现后，执行后端自动将扫描加入
`source_payload_queue`，逐漏洞收集并保存到 `finding_payload_collections`。页面读取保存结果，
不因打开页面重新调用 Assistant。载荷未执行，不代表漏洞验证成功。
队列及处理位置持久化，重启恢复已排队工作；不会自动回填所有历史导入任务。
已完成、空结果、人工取消或已知失败的条目不会自动重复提交；失败可在页面手动重试。
收集错误不改变扫描结果，队列以 partial 记录未成功项。未关联平台任务的独立扫描不进入
逐漏洞验证收集队列。远端执行扫描时，需部署本版后端才能在远端自动收集；复制扫描报告
并不会自动复制载荷表，离线导入仍需包含相关收集记录。
Assistant 最终回复支持纯 JSON 或说明文字中的单个 JSON 代码块；多个代码块有歧义时拒绝，
始终校验载荷与当前漏洞、Flow 原文的关联，不采用终端输出替代最终回复。

## 本地 CScan 连接配置

`scripts/start.sh` 按顺序选择 `REDTEAM_CSCAN_ENV_FILE`、
`$XDG_CONFIG_HOME/redteam/cscan.env`（XDG 未设置时使用 `~/.config`）、
已有的 `.codex/local-demo/cscan.env`。后端只读取 `CSCAN_*` 键值，不执行文件中的
Shell 命令；已导出的同名环境变量优先。不要将凭据文件加入 Git。

启动时执行只读 CScan API 认证检查。检查失败仍可查看已保存的本地报告，但远端
Assistant 收集不可用；启动脚本不自动创建 SSH 连接或反复打开登录页面。
使用 Cloudflare 时需保持对应的 SSH 本地转发运行，浏览器登录本身不等于隧道可用。
可单独运行 `REDTEAM_CSCAN_ENV_FILE=/绝对路径/cscan.env node backend/scripts/check-source-environment.js --api`
核实配置与通道。载荷收集界面会保留缺少凭据、连接失败、HTTP 状态等安全诊断，
未知异常仍隐藏细节。配置变更后需重启本地后端，已有失败记录在重试后更新。
