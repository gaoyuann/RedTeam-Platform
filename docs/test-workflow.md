# 测试流程衔接

## 主界面统一任务流程

首页负责发起、继续及打开最近任务；顶部模块分别展示拓扑、扫描、想定与预案、执行和评估等内容，模块内不再重复展示完整流程页签。返回列表或首页只切换视图，不清空当前任务、预案编辑和证据；打开同一任务继续原阶段，打开其他任务才切换上下文。列表提供“继续当前任务”。后台扫描结束时只更新对应记录，不抢占用户正在浏览的任务列表。

连续操作回归位于 `frontend/test/task_continuity_checks.h`，由 `ctest --test-dir build -R '^ui-task-journey$' --output-on-failure` 运行。该检查从首页的实际按钮开始，点击创建、顶部模块与子功能、引用已有来源、保存、提审、确认执行、报告生成，再核对返回首页／列表时保留未保存内容、重复点击不重复执行及旧响应不覆盖新任务。界面使用隔离 API 样例；后端真实本地请求、curl 进程、预检执行及报告导出由 `backend/test/intelligent-loopback-workflow.test.js` 验证，模型回答使用替身。

本次验证：新增连续流程 CTest 和 1.5 倍缩放专项通过，完整 Qt 程序直接运行 1312 项通过；原 120 秒聚合 CTest 曾超时，未延长其上限。后端命令 `node --experimental-test-module-mocks --test test/intelligent-loopback-workflow.test.js test/task-closed-loop.test.js test/source-flow-execution.test.js` 在 `backend/` 下运行，13 项通过。真实模型效果、部署工具镜像和实际被测系统仍需在目标环境联调；没有自动部署或操作真实目标。

首页是统一入口；进入任务后，由顶部模块及其子功能分别负责拓扑、扫描、想定与预案、执行和评估，共享同一任务。模块内只显示对应页面，不再提供另一排完整流程导航。任务管理只负责列出、选择和管理任务；首次双击或右键打开另一任务后，在同一主窗口按状态定位：扫描中的任务进入脆弱性扫描，待审批任务进入任务方案，有运行记录的活动任务进入攻击测试，结束的执行进入测试结果与评估，资产探测任务进入拓扑。更换任务与单纯打开任务不同：在某功能内更换任务时保留当前功能。

扫描、方案、攻击和结果入口均复用同一个任务及其页面实例。不选择任务时提供选择已有任务和发起测试，主界面不再构建独立扫描、独立攻击页面，也不再显示“独立操作”按钮。旧页面编号 10／11 重定向到统一入口；后端记录不转换、不删除。任务工作台复用原 `FlowPage` 与既有阶段页；内部阶段容器仅用于承载对应页面，阶段页签隐藏，返回任务列表操作保留。返回列表不会退出当前任务，列表提供“继续当前任务”；没有另建独立扫描／执行表单。

从任意主模块发起新测试，默认先在主界面展示本任务的扫描进度与全部发现；生成方案、确认执行和查看结果继续使用该任务。测试评估新增“测试结果与评估”入口；捕获与网络分析保留为明确标注的辅助工具，不虚构与父任务的自动关联。模板的执行入口先关联任务方案，不再跳到无任务的独立执行表单。

本次对照的是本机 PentAGI Qt 参考实现：`main_window/MainWindow.cpp` 将扫描结果入口映射到已有 `VulnerabilityScanPage`；该页面的 `openTaskDetails` 可打开以原 Flow ID 为上下文的详情窗口。参考项目确有详情窗口，复用的仍是同一任务页面和记录；这不等于需要在本项目主界面保留另一套独立扫描／执行流程。本次不修改参考项目。


本轮模块职责修正验证：主程序和 UI 回归目标构建通过；完整界面回归串行运行 1384 项通过；150% 缩放下连续流程 83 项、模块路由 111 项、源码／拓扑显示 89 项通过。各模块的内部阶段页签隐藏，回归改为实际点击顶部模块与子功能，并检查其他阶段页面不可见、任务及未保存草稿保留。截图采用隔离模拟数据，未验证真实目标执行。

## 当前默认入口（恢复原流程）

普通网络目标新任务不再写入 `workflow_mode=intelligent`，直接复用重构前的 pipeline：扫描 → 分析 → 生成预案 → 建立本任务草稿、提审、管理员批准 → 执行 → 结果。授权范围和冻结版本执行规则继续生效。已有 intelligent、staged、源码／程序及资产探测任务按各自保存的配置处理，不批量修改历史数据。

扫描和生成结束进入同一任务的方案审核；原流程需在方案页选择已生成的来源，建立草稿并提审。攻击页在待审批时提供“审阅本任务方案，确认后执行”，无需切换任务或另建独立执行。任务模式的提示和按钮放在始终可见的页面容器中，避免被隐藏的独立执行页签一并遮蔽。整体任务执行默认展示本次方案步骤，结束后从执行页进入同任务结果；失败执行同样保留证据。进入结果不自动生成报告。

顶部预案模块保留为方案与知识库的管理入口；主流程中的方案审核仍是执行前的确认环节。下文智能自动送审描述仅适用于已有 intelligent 任务。独立扫描和执行的历史数据保留；逐漏洞验证继续复用现有组件，主界面不再提供另一套独立操作入口。

本版复用 `pipelines` 作为“本次测试”的关联记录，扫描、预案、执行证据、评估及报告继续使用现有模型。新建普通测试复用原有扫描、分析、预案审阅与执行流程；七模块提供同一任务的不同视图。

## 选择已有预案与逐漏洞攻击（当前入口）

攻击测试页并列提供“选择已有预案”和“逐漏洞攻击测试”。前者定位同一任务的整体预案与来源选择，保留原有建立任务草稿、审阅、提审及批准执行流程，不要求针对每个漏洞调用模型生成预案；已有草稿和编辑不被替换，整体任务须处于后端允许审阅的状态；扫描部分失败但保留有效发现的普通网络任务可使用下文的明确手动继续分支。后者直接选择本任务扫描发现，打开攻击验证窗口，继承具体目标和发现编号，不再强制绕到逐漏洞预案列表。

扫描列表与证据详情中的“逐漏洞攻击测试”直接进入攻击模块；独立历史扫描仍先通过已有 `test-context` 接口关联到任务。已有方案下拉和“使用此方案”在验证窗口直接显示，不必展开高级设置。自动准备、AI 调整和载荷生成都是按需选项；尚缺入口或执行条件时仍须补充，确认和执行版本规则继续生效。已有逐漏洞预案管理入口及源码／程序专项保留，未改变扫描调度器或后端执行接口。

两条路径均复用当前任务和目标，不再次创建父任务、不要求重新输入 IP。打开入口只读取既有来源并建立对应验证记录，不自动调用模型、生成载荷或启动攻击。重复点击定位已有验证窗口、保留其中草稿；切换任务关闭旧窗口，旧详情响应不能创建旧任务验证。

修改文件为 `frontend/src/pages/ExecutionPage.{h,cpp}`、`FlowPage.{h,cpp}`、`TaskPlanPage.{h,cpp}`、`ScanPage.cpp`、`FindingVerificationDialog.cpp` 和 `frontend/src/MainWindow.cpp`；回归更新 `frontend/test/task_continuity_checks.h` 与 `workflow_handoff_checks.h`。

本轮验证：应用和 Batch16Checks 构建通过；`QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 ./build/frontend/RedTeam-Platform-Batch16Checks` 完整界面回归 1419 项通过；`REDTEAM_HANDOFF_ONLY=1` 在 2 倍缩放下最终通过 330 项（含截图保存及场景筛选复位），连续选择已有预案到报告的 `REDTEAM_TASK_JOURNEY_ONLY=1` 在 2 倍缩放通过 84 项；`ctest --test-dir build -R '^ui-finding-payload-artifacts$' --output-on-failure` 为 1/1 通过。后端在 `backend/` 执行 `node --experimental-test-module-mocks --test test/finding-verification.test.js test/intelligent-loopback-workflow.test.js test/task-closed-loop.test.js`，30 项通过。回归使用隔离任务、模型替身和本地执行样例，不代表真实目标攻击成功。最终只复位无关场景筛选的改动经 2 倍衔接专项覆盖；预览保存在 `build/ui-attack-options-20261101/`，构建产物不提交。

## 扫描部分失败后手动选择已有预案

原来整体预案仅允许 `awaiting_approval` 状态建立草稿，导致网络扫描保存了有效发现、但部分子检查失败时，已有预案目录仍整行禁用。现对“扫描失败、尚无整体运行及草稿、扫描工具与逐漏洞测试已确认停止、保留漏洞候选”的普通网络任务开放明确的手动继续路径。运行中、工具停止未知、没有漏洞候选、纯信息记录、资产探测、源码／程序及历史 staged 任务沿用原限制。

`GET /api/pipelines/:id/plan` 与 `/plan/sources` 在保留原 `data` 格式的基础上添加 `meta.plan_selection`，包含 `can_create_from_existing`、`requires_scan_failure_confirmation`、`pipeline_status` 和 `reason`。客户端只有收到服务端明确允许的元数据才启用失败任务的来源预案与“基于已有发现建立草稿”；旧服务没有元数据时继续保持原限制。

用户明确选择来源并点击建立草稿时，`POST /api/pipelines/:id/plan` 发送已有 `playbook_id` 及新增 `continue_after_scan_failure:true`。后端在事务内重新检查状态、工具停止和来源权限；全部验证成功后才建立草稿，将任务转为待审批。重复创建、来源已失效或任务状态发生变化均不覆盖已有记录。不会因为读取页面、刷新目录或缺少明确参数就自动改变任务状态。

扫描步骤仍为 `failed`，原错误、扫描记录与发现均保留；原错误及用户选择记录另写入 `result.manual_scan_continuation` 和任务活动／方案审计。之后仍按原提审、管理员批准、冻结执行快照推进，不重新扫描，不自动调用模型生成预案。提审和批准再次检查工具停止、授权和快照；执行完成日志明确原扫描失败记录继续保留。

从预案库进入时，若任务方案仍在读取，页面保留所选来源，等待服务返回任务状态后继续建立草稿；连续点击只创建一次，切换任务使旧选择失效。攻击测试页的失败任务提示提供同一“选择已有预案”路径。

历史任务配置 `auto_execute=false` 时，管理员批准前的确认窗口明确说明会启用本任务执行。取消不提交；确认才随 `POST /api/pipelines/:id/plan/approve` 发送布尔值 `enable_execution:true`。服务继续校验管理员权限、提审版本、授权和工具停止状态，审批成功时将该任务的 `auto_execute` 设为 `true` 并写入审批审计；没有明确标识的旧客户端仍返回 409，不批量改写历史任务。

补充验证：`backend/test/intelligent-loopback-workflow.test.js` 覆盖正常原流程、历史智能流程，以及失败扫描后手选已有预案、历史关闭执行后明确启用两条恢复路径。恢复路径保留失败扫描及候选，实际运行本机 curl、保存证据并导出报告，不调用模型。`frontend/test/task_continuity_checks.h` 同时覆盖正常与失败扫描的主窗口连续操作；`manual_task_plan_checks.h` 覆盖来源延迟读取、重复选择和取消／确认启用执行。

改动文件：`backend/src/services/taskPlan.js`、`backend/src/routes/taskPlans.js`、`backend/src/services/pipelineEngine.js`、`frontend/src/pages/TaskPlanPage.{h,cpp}`；回归：`backend/test/manual-task-plan.test.js`、`frontend/test/manual_task_plan_checks.h` 与 `frontend/test/batch16_context_checks.cpp`。未新增数据库迁移，也不改写历史扫描状态。

验证：主程序与 UI 回归构建通过；`REDTEAM_MANUAL_PLAN_ONLY=1` 在 1／2 倍缩放分别通过 23 项，覆盖可选、未知停止禁用、来源读取失败、旧服务兼容、重复点击只提交一次、成功后转入原草稿提审流程。后端新增用例和原预案、源码与闭环回归 35 项通过。`npm test` 完整结果为 743 项通过、3 项跳过、0 失败（真实 SAST／cppcheck 及真实工具联调检查跳过）；完整 UI 回归为 1437 项通过。新增测试首轮因迁移已预置 admin、以及不存在预案应返回 404 而非 403 的夹具预期错误失败；已改为兼容预置账号并明确断言 404，没有放宽业务断言。截图为隔离样例，保存在 `build/ui-manual-plan-20261101/`。

此修复只打通明确选择已有预案的人工分支，不表示 ReAct 参数检查的无效模型决策和 arjun 超时已修复。代码验证期间未修改用户真实任务、未重扫、未审批或发起攻击；运行中的后端需要加载更新后才能返回新元数据。

本次适配补充验证：`npm --prefix backend test` 为 746 项通过、3 项跳过；现有 CMake 应用与 Batch16Checks 构建通过。手选预案专项在 1 倍缩放通过 28 项，1.5 倍缩放含截图保存通过 29 项；正常与扫描失败两条连续主窗口流程通过 157 项，`ctest --test-dir build -R '^ui-task-journey$' --output-on-failure` 通过。完整 Qt 程序直接运行通过 1518 项；`ctest --test-dir build -R '^ui-context-1$' --output-on-failure` 达到既有 120 秒上限，未改动断言或超时，不能将该 CTest 记为通过。

运行时需同步加载前后端修复；更新前检查活动任务及待迁移项，避免旧进程继续使用缺少元数据的接口。加载新版本后，在同一任务的攻击测试页选择已有预案继续，扫描失败记录及已有发现仍可追溯。

## 已有 intelligent 任务的操作路径

1. 从任务管理打开已有 intelligent 任务，沿用任务保存的目标、授权范围与流程模式；新建普通目标任务使用前文恢复的原流程。
2. 扫描成功后自动调用模型分析，再生成预案；生成不可用时尝试匹配适用模板。模型分析不可用会停止并保留扫描与降级参考，不把降级结果当成模型完成。生成和匹配均失败、或匹配方案缺少具体入口时，显示原因，不创建执行。
3. 后端把来源预案复制为本任务独立版本并自动送审。当前任务工作区进入“漏洞利用预案”，展示目标、方案说明和步骤；用户无需选择工具、填写参数或手动建立草稿。技术配置可从“更多”菜单展开。管理员点击“确认方案并开始测试”；普通用户等待管理员审批。批准后使用冻结快照执行，后续修改模板不影响该版本。
4. 确认成功后进入同任务“漏洞攻击测试”；启动失败保留预案和原因。执行结束后，当前执行视图进入结果评估。查看实际证据、系统结论和失败原因；失败、未达成和证据不足的记录同样可以评估，执行结束不等于验证成立。
5. 在同一任务结果页核对统计与来源，显式生成报告，再导出。系统管理中的报告生成与报告索引继续复用这些记录。

需要逐漏洞补充验证时，可从扫描发现进入“逐漏洞攻击测试”，直接选用已有方案；自动生成是可选操作。具体漏洞详情支持 AI 准备、调整、载荷管理和独立执行记录，复用原发现编号与证据。已有分阶段任务仍直接展示逐漏洞预案列表；检查列表与详情不自动启动模型或攻击。

智能任务与既有整体预案任务通过扫描进入逐漏洞预案时，仍可使用“查看整体编排预案”回到整体方案；旧分阶段任务不显示这个入口。源码／程序专项沿用原有创建与审批流程。

资产清单中的“在拓扑中查看”只切换当前文档的视图并定位同一节点，不新建资产、扫描或网络关系。鼠标与键盘选择均更新当前对象；返回资产视图保留选择。

## 新任务与旧任务

- 已有的智能测试保存 `config.workflow_mode = "intelligent"`，同时保留 `task_mode = "assessment"`。按扫描、分析、生成、自动送审、批准、执行推进。自动送审不表示批准，也不会启动工具执行。
- 已有 `workflow_mode = "staged"` 的任务继续在扫描阶段结束后停止，由用户选择具体漏洞验证。父任务终止状态只表示扫描阶段结束，逐漏洞执行状态和验证结论独立保存。
- 未记录 `workflow_mode` 的旧任务保留原扫描、分析、全局预案与审批行为。源码／程序测试保留专项流程。本版没有批量转换历史任务，也没有改写历史结论。
- 原独立网络扫描可通过漏洞旁的继续操作建立测试关联。沿用原扫描和发现编号，重复请求复用已有测试；不会重新扫描或自动执行攻击。已有合法归属时直接打开原任务，不重新绑定。
- 独立扫描关联不追认历史授权。新测试的授权元数据保持“未记录”；执行仍须在具体验证详情核对范围和条件。旧任务的全局预案审批仍要求原有授权记录。

## 接口

`POST /api/scan-tasks/:scanTaskId/test-context`，请求体为 `{}`，返回：

```json
{
  "status": "ok",
  "data": {
    "pipeline_id": "pipe_…",
    "task_no": "TASK-…",
    "scan_task_id": "scan_…",
    "reused": false
  }
}
```

该接口只组织已保存数据，不调用扫描器、模型或执行器。创建关联只支持已结束的普通网络扫描；运行中的记录、源码专项、资产探测记录和不一致的旧关联返回明确错误。其他用户不能关联非本人扫描；管理员可打开已有合法关联，新建关联须由扫描所有者操作。缺少现有扫描关联或任务编号迁移时明确失败，不自动修改数据库结构。

智能和分阶段模式在创建和启动时校验；不能将其用于资产探测或源码专项。更新和重新扫描保留原记录的流程模式及来源。智能任务必须通过 `POST /api/pipelines/:id/plan/approve` 审批具体版本，旧 `/:id/approve` 不可绕过；自动建草稿和送审与任务暂停在同一事务完成。

## 状态与验证

前端按测试编号、扫描编号、发现编号和请求版本处理异步响应。切换任务会使旧请求失效并关闭旧任务的验证窗口；同一任务增加扫描来源时保留打开的验证草稿。单纯切换模块不会重建任务，预案详情的未保存编辑保持原样；正在编辑一份预案时，再打开另一项会定位原窗口并提示先保存关闭。保存已有预案会保留其尝试次数和时长限制。进入评估不自动生成报告，报告继续使用已有来源指纹与停止状态校验。

回归使用内存数据库、隔离 HTTP 样例和模拟执行证据，覆盖目标建任务、自动分析与生成送审、旧分阶段结束、独立扫描关联、成功／失败出报告、审批版本冻结、重复操作及迟到响应。智能流程回归使用真实分析与生成解析逻辑，模型返回和工具执行使用替身；不代表真实模型方案质量或实际漏洞利用成功。Qt 检查覆盖新建配置、方案摘要、取消与失败重试、确认执行、同任务结果跳转及原逐漏洞路径。

本版没有建设跨测试的统一资产台账或历史变化管理。资产表与拓扑共享当前文档节点；路由观测、同网段归属、请求关系和手工关系仍按现有证据分别标记，主机在线不能作为设备相连的证明。预案列表按原始扫描发现编号组织，不额外宣称跨扫描自动去重。真实扫描器、模型、靶场、加密锁与目标部署环境仍需联调验收。

## 改动文件与验证命令

- 页面路由与上下文：`frontend/src/MainWindow.cpp`、`frontend/src/pages/FlowPage.{h,cpp}`。
- 资产、扫描和预案入口：`TopologyPage.{h,cpp}`、`ScanPage.{h,cpp}`、`TaskPlanPage.{h,cpp}`。
- 逐漏洞预案列表：`frontend/src/pages/FindingPlanPanel.h`，复用已有扫描结果和验证详情接口，没有新增第二套预案数据库。
- 验证、证据与评估：`FindingVerificationDialog.{h,cpp}`、`ExecutionPage.{h,cpp}`、`TaskExecutionPanel.{h,cpp}`、`TaskResultsPanel.cpp`（均位于 `frontend/src/pages/`）。
- 后端：`backend/src/routes/{pipelines,scans}.js`、`backend/src/services/{pipelineEngine,scanAgentConfig,scanTestContext}.js`。
- 回归：`backend/test/{intelligent-workflow,scan-test-context,staged-test-flow}.test.js`、`frontend/test/{intelligent_workflow,workflow_handoff,finding_plan}_checks.h` 及现有 `batch16_context_checks.cpp`。

验证命令：

```sh
cmake --build build --target RedTeam-Platform RedTeam-Platform-Batch16Checks -j 4
cd backend && npm test
# 回到仓库根目录
ctest --test-dir build -R '^ui-context-' --output-on-failure
```

可用 `QT_QPA_PLATFORM=offscreen REDTEAM_HANDOFF_ONLY=1 QT_SCALE_FACTOR=1 build/frontend/RedTeam-Platform-Batch16Checks` 单独运行衔接检查；缩放值同样检查 `1.25` 和 `1.5`。

可用 `REDTEAM_INTELLIGENT_ONLY=1` 替换上述筛选变量，单独验证智能流程。部署需同时更新前后端，新流程标识不需要数据库迁移；历史任务不自动转换。

智能流程适配时，首轮完整 Qt 回归在“源码生成步骤自动建立任务草稿”失败：新增摘要通过可写 JSON 下标读取空预案，意外插入状态字段，使页面把空预案判断成已有草稿。已改为只读 `value()` 访问，并补充等待生成时保持空预案、隐藏就绪摘要的检查，保留原源码流程断言。

本次验证：后端 `npm test` 720 项通过、2 项依赖真实 SAST 工具的检查跳过；最后的智能流程、分阶段兼容和预案推荐专项共 15 项通过。应用和 Qt 回归目标编译通过。`ctest --test-dir build -R '^ui-context-' --output-on-failure -j 3` 中 1 倍缩放通过，另外两档达到原有 120 秒上限；分别运行 `-R '^ui-context-1\.25$'` 和 `-R '^ui-context-1\.5$'` 后通过，耗时约 102 秒和 110 秒。未放宽断言或超时限制；并行渲染负载是超时原因的推断，后续建议逐档执行完整界面回归。

## 本轮恢复原流程的验证

修改集中在 `FlowPage.cpp`、`ExecutionPage.{h,cpp}`、`playbookRecommendations.js`，补充 `intelligent_workflow_checks.h` 与 `intelligent-workflow.test.js` 的旧模式覆盖，并按当前七模块顺序校正 `batch16_context_checks.cpp` 的页面宿主断言。

- `cmake --build build --target RedTeam-Platform RedTeam-Platform-Batch16Checks -j 4` 通过。
- `cd backend && npm test`：724 项通过，2 项跳过。新增原流程回归覆盖扫描、草稿、提审、权限／版本冲突、冻结执行、成功／失败证据、重复批准和报告复用。扫描、模型与执行使用隔离替身。
- `REDTEAM_INTELLIGENT_ONLY=1 ctest --test-dir build -R '^ui-context-' --output-on-failure -j 3` 和 `REDTEAM_HANDOFF_ONLY=1` 同命令在三档缩放下通过；前者包含恢复原模式及历史智能模式兼容。
- 首轮后端完整检查在 `playbook-matcher.test.js` 的范围推荐断言失败：警告被提前排除，失败工具被误标记已检查。修复为保留范围内诊断供完成状态判断，诊断仍不作为匹配证据；重跑通过。
- 首轮完整 Qt 检查暴露沿用旧模块顺序的宿主断言，已按当前模块对应页面校正。后续完整三档并行检查达到现有 120 秒超时；单独重跑 `ctest --test-dir build -R '^ui-context-1$' --output-on-failure` 通过（102.32 秒）。高缩放完整回归仍未完成，不能宣称三档全量通过；未放宽断言或超时限制。

本轮未启动真实扫描器、模型服务或靶场，不代表已验证实际漏洞利用成功。部署需要同时更新客户端和后端的推荐修复。

## 主界面统一适配的改动与验证

改动文件：`frontend/src/MainWindow.{h,cpp}`、`pages/FlowPage.{h,cpp}`、`widgets/ModuleRibbon.cpp`；同步 `frontend/test/{batch16_context_checks.cpp,intelligent_workflow_checks.h,scan_presentation_checks.h,unified_shell_workflow_checks.h}` 与本文、`frontend-ribbon.md`。没有修改后端 API、提示词或数据库。

- 应用与 Qt 检查目标通过现有 `cmake --build build --target RedTeam-Platform RedTeam-Platform-Batch16Checks -j 4` 编译。
- `ctest --test-dir build -R '^ui-context-1$' --output-on-failure` 完整检查通过（97.58 秒）。最后的任务概况选择边界修复另由统一主界面专项覆盖。
- `REDTEAM_UNIFIED_ONLY=1 ctest --test-dir build -R '^ui-context-' --output-on-failure` 覆盖任务管理真实双击、四种任务状态定位、模块间同任务同实例、无任务选择入口、兼容页面编号、只读导航以及从概况更换任务；三档缩放通过。可通过 `REDTEAM_UNIFIED_SCREENSHOT_DIR` 保存实际 Qt 主窗口截图。
- `REDTEAM_RIBBON_REVIEW_ONLY=1` 的主界面导航专项通过 502 项检查；`REDTEAM_SCAN_PRESENTATION_ONLY=1` 的共享任务扫描、源码和拓扑展示通过 73 项检查。
- 首轮完整检查失败于原“主界面创建独立扫描”的旧行为断言。该场景已改为选择任务、共享任务发起入口和同任务扫描来源；保留源码、日期可读性、发现列表及拓扑布局断言。导航专项同时检查更换任务后保留明确选择的功能，新增任务则统一先展示本次扫描。

已查看隔离样例下的实际 Qt 截图，确认没有旧阶段页签或无任务独立执行表单。未连接真实模型、扫描器或靶场；本轮验证说明主界面路由和页面共享一致，不宣称完成实战利用验收。

## 原流程适配与演示核对

本轮按用户要求不合并其他未合入分支；仅获取并比较 origin，当前 HEAD 保持原分支。验收范围为重构前流程与当前 Qt 主界面之间的衔接，不依赖指定远端靶场。

原普通任务仍按扫描、分析、生成来源预案、建立本任务草稿、提审、管理员批准、冻结版本执行、结果与报告推进。逐漏洞验证仍是同一任务中的独立验证分支，保留原发现、方案版本和尝试记录，没有并入整体预案或要求两边重复执行。

方案页新增明确的“方案范围”选择：整体任务方案／逐漏洞验证方案。任务头部和攻击页的“审阅任务预案”明确回到整体方案；历史 staged 任务仍只允许原逐漏洞分支。切换视图保留已有编辑，批准和执行接口不变。攻击页优先显示实际运行中的逐漏洞验证；有整体运行与逐漏洞历史时同时给出状态，避免只显示“主预案尚未执行”。

### 演示操作路径

1. 在主界面发起测试，核对目标和原有授权范围，创建并开始。主界面先显示本任务扫描与全部发现。
2. 普通整体任务生成方案后，进入“整体任务方案”，沿用原来的来源预案、建立草稿、提交审批和批准执行。旧 intelligent 任务按原记录自动送审。
3. 单独验证某个漏洞时，从扫描发现选中具体漏洞进入“逐漏洞验证方案”；准备测试后，载荷代码页可查看已有片段或生成本漏洞验证代码。需要步骤载荷时沿用原“查找或生成、预览、绑定”操作。
4. 源码原 Flow 载荷整理、Python 改写、生成验证代码和实际目标 HTTP 对照保留各自原入口与条件。代码生成不会自动执行；整理结果可为空。准备本地载荷测试只验证本地程序，不能替代实际目标的漏洞结论。
5. 确认具体方案后执行，在主界面攻击模块查看同任务步骤与证据，结束后进入评估，显式生成和导出报告。失败执行也保留记录。

正文由 12pt 调为 13pt；公共输入、表格和按钮主要使用 18px，常用状态说明同步放大，源码等宽字体设为 13pt。主导航、按钮及表格行高同步调整；小窗口使用滚动和收紧留白，不通过缩小正文容纳内容。

本轮改动集中在 `TaskPlanPage.{h,cpp}`、`FlowPage.cpp`、`TaskExecutionPanel.cpp` 的页面选择及状态显示，公共字体样式与常用页面字号。`intelligent-loopback-workflow.test.js` 增加当前默认原流程的本机扫描、实际 curl、证据和报告验证。后端模型答复采用固定样例，工具和 HTTP 请求真实执行，仅访问本机测试服务；没有更改生成提示词、后端业务接口或运行数据。

本轮验证命令与结果：

- 现有 CMake 应用、Batch16Checks 与 SourceScanDetailChecks 编译通过。
- `cd backend && npm test`：725 项通过、2 项跳过。包含当前原模式的真实本机扫描／curl／证据／报告链路，以及载荷收集、生成、绑定和执行边界检查。
- `REDTEAM_INTELLIGENT_ONLY=1`、`REDTEAM_UNIFIED_ONLY=1` 与 `REDTEAM_HANDOFF_ONLY=1` 的 Qt 专项在 1／1.25／1.5 缩放通过。新增断言覆盖整体审核从逐漏洞列表返回、逐漏洞活动状态不被主预案和场景筛选覆盖。
- `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1.5 build/frontend/RedTeam-SourceScanDetailChecks` 通过；方案页及表单的实际 Qt 截图已核对。
- 首轮完整 Qt 回归失败于大字号下小窗口画布可用高度不足，收紧拓扑内部留白后扫描／拓扑专项通过。后续完整回归末段达到原 120 秒时限，未放宽断言或时限；完整结果需与上述专项分别看待。

最终完整程序复核：`QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 build/frontend/RedTeam-Platform-Batch16Checks` 通过 1250 项检查，计时 99.79 秒。该次没有并行执行其他 UI 专项，末段逐漏洞确认、启动、失败记录、评估返回全部完成。先前 CTest 120 秒超时的确切原因未独立确认，不宣称修改了 CTest 时限或其超时结果；直接运行的完整程序已排除同一路径必然阻塞。
