# 任务删除与列表刷新

已结束或尚未启动的测试任务可通过 `DELETE /api/pipelines/:id` 从任务列表删除。后端记录删除标记，保留扫描、漏洞、报告、验证和重试来源；这不是物理擦除证据。重复删除返回成功，任务编号不会复用，原创建请求不会复活已删除任务。

运行中、待确认、关联扫描未结束、工具或漏洞验证停止未确认时，返回 409 并说明原因。删除后列表、精确编号查找和分析索引不再列出该任务；历史报告及已有来源仍可只读查询，任务不能更新或重新启动。

工具调用须处于已完成、失败、超时或取消的终态，且停止结果明确为 true；缺失、无效 JSON 或未知停止结果均返回 409，不隐藏任务。旧记录未保存停止确认时同样需要先核对原调用。

部署需随正常后端启动应用 `041_task_deletions.js`；迁移只增加删除标记表，不改写已有任务。旧数据库仍能查询，删除操作会提示更新后端。回退时应同时保留该表和使用删除过滤的后端版本，避免旧版本重新显示任务。

列表后台刷新期间保留当前行的打开与右键操作；密集状态事件合并刷新，数据未变时不重绘，部分变化时复用未变化的行，读取失败时清空可操作行并明确显示错误。删除失败以非阻塞弹窗显示后端原因，避免刷新覆盖唯一提示。

## 修改范围

- 后端：`routes/pipelines.js`、`routes/scans.js`、`routes/topology.js`；`services/taskDeletion.js`、`taskIdentity.js`、`taskAnalysisIndex.js`、`topologyLinkedTasks.js`、`scanTestContext.js`；数据库迁移 `041_task_deletions.js`。
- 前端：`pages/FlowPage.cpp`、`FlowPage.h`。
- 回归：`backend/test/task-deletion.test.js`、`task-statistics.test.js`、`frontend/test/batch16_context_checks.cpp`。

## 验证

后端在 `backend/` 运行：

```sh
node --experimental-test-module-mocks --test test/task-deletion.test.js test/pipeline-list-performance.test.js test/task-identity.test.js test/task-analysis-index.test.js test/task-statistics.test.js test/scan-test-context.test.js test/topology-api.test.js test/topology-workflow.test.js test/scan-agent-api.test.js test/source-api.test.js
```

前端使用仓库现有构建目录：

```sh
cmake --build build --target RedTeam-Platform-Batch16Checks RedTeam-Platform -j 4
QT_QPA_PLATFORM=offscreen ./build/frontend/RedTeam-Platform-Batch16Checks
```

列表接口仍兼容原来的全量响应；本次减少前端无效重建与刷新等待，未增加分页，也不把本地测试结果等同于实际运行环境的性能测量。

本次本地验证结果：后端上述 67 项测试全部通过；前端任务列表专项 16 项检查、完整界面回归 1260 项检查全部通过；`RedTeam-Platform` 与 `RedTeam-Platform-Batch16Checks` 构建成功。前端使用现有 Qt 构建配置及 offscreen 模式，未启动实际客户端服务或迁移真实数据库。
