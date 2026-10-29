# 报告文件存储约定

## 服务器运行产物

旧版 Run 报告的 DOCX、PDF 和模板导出统一写入仓库根目录下的 `data/reports/`。目录由导出服务自动创建，不依赖服务启动时的工作目录。该目录属于运行数据，已加入 `.gitignore`，不能提交新生成的报告。

对应实现为 `backend/src/services/reportDocx.js`、`reportPdf.js` 和 `reportTemplate.js`。文件名分别为 `report_<run_id>.docx`、`report_<run_id>.pdf` 和 `report_<run_id>_tpl.docx`；同一 Run 再次导出同一格式会覆盖该 Run 的旧导出副本。

`POST /api/reports/generate` 只保存数据库报告记录，不生成 Word 文件。`POST /api/reports/generate-and-export`、旧报告的 `GET /api/reports/:reportId/export` 及模板导出接口会调用上述文件生成服务。客户端“在 WPS 中打开”需要下载报告，也可能触发导出。扫描执行本身不自动生成这些 DOCX 文件。

任务追溯快照报告保存于数据库，其 JSON、HTML、PDF、DOCX 导出在内存生成并发送给客户端，不在服务器另存导出文件。不要为了统一目录而给这条链路增加落盘副本。

## 客户端与资料文件

用户主动导出报告时，保存位置由文件选择框决定。任务结果面板和旧评估页面的 WPS 文件统一保存于应用缓存的 `report-exports/` 专用目录，每次下载使用独立子目录，避免覆盖已在 WPS 中打开或编辑的副本。旧评估页面的子目录以 `legacy-` 开头；文件完整保存后才打开 WPS，失败时不留下本次不完整副本。这些缓存不属于服务器报告目录。

`docs/` 中的手册、汇报材料和明确保留的示例文档属于项目资料，不作为日常运行报告的输出位置。

## 历史数据与兼容

新增忽略规则不会移动、删除既有报告，也不会修改数据库记录或下载接口。历史上已经被 Git 跟踪的 `data/reports/` 文件仍保持原状；`.gitignore` 不会自动取消对它们的跟踪。后续如需从版本库移除历史运行产物，应单独核对保留用途并备份，不能直接清空目录。

检查新增运行文件是否被正确忽略：

```sh
git check-ignore -v data/reports/report_run_ignore-check.docx
```

报告和数据库、证据一样属于需要保留的运行数据。备份与恢复应继续包含 `data/reports/`，不能因其被 Git 忽略就排除。
