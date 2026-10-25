# CScan 目标扫描与验证执行接入

## 已选方案
用户输入源码目标，Node 后端调用 CScan GraphQL 创建 Flow，远端 Agent 获取源码并静态审计。平台保存原报告与可取得的同 Flow 源码副本，结构化发现；用户选择发现后，原 Flow 的 useAgents=false Assistant 整理已有载荷，再由平台解析模型生成具体验证步骤。确认方案后交给本项目已有 executionEngine / toolRunner 执行，结果写回任务数据库。

这是对 pentagi-v3 漏洞扫描工作流的后端适配。原版界面在 Qt 端编排；本项目在 Node 端编排，凭据不下发给客户端。此前移入的独立本地源码上传模块保留为参考与原版回归测试，已从生产主程序的链接和页面执行路径移除。

## 两边源码对应关系

| 环节 | pentagi-v3 当前源码 | 本项目实际接线 |
| --- | --- | --- |
| 提交目标 | VulnerabilityScanPage::buildScanInput / createScanFlow → PentagiService::createFlowWithConfiguredProvider | PentagiSourceScanHost → POST /api/scan-tasks/source-flow → sourceFlowWorkflow → executeScan → auditSources → scanCscanTarget → createCscanClient.create |
| 状态与原报告 | loadSelectedReport → fetchFlowReport，保存报告快照 | runCscan 查询 Flow、task、subtask；scanCscanTarget 保存 raw_output；完成条件检查所有任务与子任务 |
| 增量与最终结构化 | processIncrementalSubtasks / analyzeSelectedFlowReport → OpenAiCompatibleService | cscanProgress / parseNativeReport → callLlm，sourceAuditNative 校验、合并并保存 source_finding |
| 原 Flow 载荷整理 | requestPentagiPayload → createAssistant / listAssistantLogs，useAgents=false | findingPayloadArtifacts → 相同 GraphQL 协议，持久化 marker、assistant_id、来源和原文 hash |
| Python 改写 | requestPythonPayload → OpenAiCompatibleService | findingPayloadArtifacts.startPythonRewrite；仅生成工件，不执行 |
| 生成验证任务 | AttackFlowCreationJob → createAttackFlowsSequentially → createFlowWithConfiguredProvider(job.prompt) | POST .../verifications/:id/prepare → 原 Flow 载荷整理 → 现有 generatePlan / saveVerificationPlan |
| 实际执行 | 新 PentAGI Flow；后端 Agent 调用其工具运行环境 | POST .../:id/start → confirmAndStart → launchVerification → executionEngine.executeRun → toolRunner.runTool |
| 结果 | AttackFlowRecord 绑定源扫描 Flow，后续报告/证明解析 | execution_steps / execution_attempts / evidence_records → finding_verification_attempts / assessments → verificationDetail / taskResults |

参考源码位于本机 pentagi-v3/src/ui/pages/scan/VulnerabilityScanPage.cpp；复用协议的参考版本见 frontend/vendor/pentagi-source-scan/UPSTREAM.json。没有把原版“新攻击 Flow 已创建”视为验证成功。

~~~mermaid
flowchart LR
 UI[平台 Qt 源码页] --> API[Node 平台 API]
 API --> Scan[CScan GraphQL 扫描 Flow]
 Scan --> Agent[远端 Agent 与其工具环境]
 Scan --> Reports[原报告与同 Flow 源码副本]
 Reports --> Findings[平台模型结构化发现]
 Findings --> Collect[原 Flow Assistant 整理已有载荷]
 Collect --> Plan[平台模型生成并冻结验证方案]
 Plan --> Confirm[用户核对目标与步骤]
 Confirm --> Engine[平台 executionEngine]
 Engine --> HTTP[Node 内置 HTTP/TCP 请求]
 Engine --> Tools[Docker 或 Podman 工具容器]
 HTTP --> DB[执行记录与证据回写]
 Tools --> DB
 DB --> UI
~~~

## API 与任务身份
- POST /api/scan-tasks/source-flow：target、可选 runtime_target、authorization_confirmed=true、request_id。返回 pipeline_id、task_no、scan_task_id。同一请求编号与内容返回原任务；内容变化拒绝，不自动重新扫描。
- GET /api/scan-tasks/:id：状态、报告、源码清单、最终发现和阶段预览；正文使用既有 /source-file?id= 获取，支持 .c 文件的同 Flow 副本。
- POST /api/pipelines/:id/verifications：选中 finding_id，建立逐发现验证记录。
- POST .../verifications/:verificationId/prepare：expected_revision；自动核对/收集原 Flow 载荷，再调用现有结构化方案生成器。失败保留旧方案与收集记录；缺运行入口返回 needs_conditions。
- 既有 /generate 继续兼容；/prepare 是新界面的准备入口。既有 /payloads/collect、/payloads/python、/payloads/cancel 保留。
- POST .../:verificationId/start：revision、fingerprint、confirmed=true、request_id；生成独立机械执行 run。同一启动请求返回原 attempt。
- GET .../:verificationId：冻结方案、attempt、原始步骤、脱敏证据、自动判据与人工意见；execution_backend 明确标识 platform-executor。
- /cancel 复用原执行器取消机制。

源码目录地址与程序运行入口分别保存；不会把 /source/ 自动推断成程序验证入口。源码副本只证明取到了对应文件；不证明整个项目已覆盖，也不证明与部署版本一致。

## 现在实际能执行什么
1. 冻结方案中的 target-request：后端 Node 进程执行有界 HTTP/HTTPS 和 TCP 请求；不需要 PentAGI 或工具镜像。支持正常对照、验证请求与响应证据。
2. 方案中的已有工具 ID：经过编译、目标范围检查与预检后，由 toolRunner 的 IMAGE_MAP 选择已有工具镜像，Docker/Podman 启动工具容器。验证调用设置 requireContainer，容器不可用时明确失败，不回退为宿主机脚本执行。
3. 已收集的脚本/Python 改写是带来源的工件，不会凭 scripts.content 自动执行。需要转成平台支持的具体工具参数，或未来补专用的隔离脚本运行适配器。不能宣称已支持 PentAGI Agent 的所有任意命令能力。

## 依赖和配置
- 扫描与原 Flow Assistant 整理仍依赖 CScan/PentAGI：CSCAN_API_URL、CSCAN_TOKEN_FILE 或 CSCAN_API_TOKEN、CSCAN_PROVIDER；该后端 Agent 的模型、工具容器与靶机连通性由其自身部署负责。
- 报告结构化、方案生成、可选 Python 改写依赖平台现有模型配置：system_config 的 llm 项，或 LLM_BASE_URL、LLM_MODEL、LLM_API_KEY。
- 三栏完整源码正文依赖 CSCAN_WORK_DIR 能读取 CScan workspace/work 的 flow-ID/src。CScan 与平台若分机，须提供对应只读共享目录或另接文件读取服务；GraphQL 任务报告本身不包含源码全文，缺副本时只展示报告定位与依据，不生成伪源码。
- 内置验证需要后端到声明运行入口的网络连通；容器工具还需要 Docker/Podman 与现有 rt-* 镜像。
- 任务/验证表使用现有迁移（含 037_task_identity），本次不新增数据库迁移。不复制前端独立 SQLite 的记录到平台任务。
- 真实验证须单独声明可访问、在任务范围内的运行入口、部署版本及所需认证。此轮仅对 127.0.0.1 模拟服务执行了请求，没有对靶场执行漏洞载荷，也没有部署或修改远端服务。

## 与继续使用 PentAGI 执行的比较

| 方案 | 还需修改 | 取舍 |
| --- | --- | --- |
| 当前：平台已有执行器 | 已接通原发现/方案/attempt/证据；补专用隔离脚本适配器才能直接执行任意 Python 工件 | HTTP/TCP 能实际执行且不依赖 PentAGI 执行；复用已有权限、冻结版本、幂等、取消与结果视图，改动最小 |
| 验证也交给 PentAGI | 新增攻击 Flow 持久映射、独立 create marker 恢复、状态/工具日志导入、stop 确认、报告判据到 evidence_records 的映射 | 工具环境可继续由 PentAGI Agent 管理；必须持续依赖其后端，不能只把 createFlow 返回 ID 当成已验证 |
| 另建独立执行服务 | worker 协议/队列、认证、镜像调度、超时停止确认、证据签收/去重、恢复和配置 | 当前已有执行器，现阶段重复建设，无需采用 |

## 超时、失败与重复
- 扫描使用 CSCAN_SCAN_TIMEOUT_MS，0 表示持续等待/人工取消；普通 GraphQL 请求默认 15 秒；创建 Flow 默认 5 分钟；交互 Assistant 创建/询问默认 10 分钟（CSCAN_ASSISTANT_TIMEOUT_MS）。
- 报告收集助手收到 ID 后最多等待 180 秒，逐请求另受网络超时限制；先存 marker 与原始回复，只有唯一标记命中才恢复创建响应丢失的助手。不重复发 mutation；失败保留原任务报告及脱敏错误类别。
- 载荷整理沿用原检查点与默认 180 秒总等待；方案模型每次最多 60 秒，最多一次修正。准备失败不自动发起验证。
- 验证时长由冻结方案 duration_ms 决定（最多 15 分钟）；单步请求 timeout_ms 为 500–30000 毫秒。执行停止后才落终态；停止未确认标为 unknown，阻止重试。
- 服务重启复用原 orphan / CScan / verification 恢复逻辑，不重放可能已执行的任务；原始报告、计划版本和执行历史保留。
- HTTP 成功、步骤完成和漏洞成立分别处理，模拟测试没有把请求成功写成 confirmed。

## 验证
后端：npm test；定向 node --experimental-test-module-mocks --test test/source-flow-execution.test.js。
新增模拟测试使用真实 API、扫描器、报告导入、计划持久化、launchVerification、executionEngine 和 target-request；只替换 CScan/模型服务并访问本机模拟目标。覆盖请求去重、原助手恢复、同 Flow 源码、载荷来源、基线/验证两次真实请求、超时停止及数据库外键。
前端：现有 build 构建 RedTeam-Platform、PentagiSourceHostChecks、RedTeam-FindingPayloadArtifactChecks、RedTeam-TaskReportExportChecks；ctest 验证目标提交、三栏联动、载荷与报告界面。

## 本轮实际核实结果（2026-10-25）
- 本地完整后端测试：node --experimental-test-module-mocks --test --test-concurrency=2 test/*.test.js，664 通过、2 跳过、0 失败（共 666）。
- 默认 npm test 并发首次运行在 scan-tool-output.test.js 的 10ms 超时子用例中失败：计时器先于 setImmediate 测试输出触发，断言未收到预期 stdout；当时同时在编译 Qt。该文件独立复验全部通过，降低全套并发后也通过。未删除用例或放宽断言；并发负载是符合现象的解释，不宣称已证明所有调度因素。
- 主程序及相关 UI 检查编译通过；pentagi-source-host、ui-finding-payload-artifacts、ui-task-report-export 三组通过。
- 新增全链路测试真实执行了回环 HTTP 正常对照和模拟验证请求，且验证超时终态、停止确认和重复请求去重；没有使用假 engine.executeRun 来伪造成功。
- 云端只读预检：CScan API 可鉴权；平台 LLM 地址、模型、密钥存在（未触发模型推理）；CScan 工作目录可读；Docker 可用；rt-recon、rt-vuln-scan、rt-web 镜像存在。Podman 不可用，当前可使用 Docker。
- 仍需逐任务明确运行入口、部署版本和认证条件；本地改动未部署，未对任何真实漏洞目标运行载荷。
- PR 对齐最新 main 后，三栏入口测试曾在提交回调前点击仍禁用的按钮，预期第三次提交未发生；已改为等待回调重新启用按钮后再点击，保留请求去重断言。命令：ctest --test-dir build -R 'pentagi-source-host|ui-finding-payload-artifacts|ui-task-report-export' --output-on-failure。
