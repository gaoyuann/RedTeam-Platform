# 执行器跨步骤会话与结果判定

执行器为每次 Docker/Podman 运行建立权限为 `0700` 的随机临时目录，并将其挂载为各工具容器的 `/tmp`。同一运行的步骤、ReAct 重试和插入步骤复用该目录，不同运行使用不同目录。因此，旧预案中 `/tmp/dvwa_jar.txt` 等绝对路径无需改动即可跨容器读取，来源预案与批准版本的步骤、参数、载荷保持原样。

普通输出目录、抓包目录、字典与模板的挂载继续使用既有路径。执行器在正常结束、业务失败、运行异常或手动中止后尝试移除临时目录；清理失败会记录不含会话内容的告警。宿主机执行模式仍使用原有本地 `/tmp`，本次新增的运行间目录隔离仅适用于 Docker/Podman。后台进程被强制终止或主机重启时无法保证执行 `finally` 清理。

结果判定保留工具原始退出码与输出，同时将以下情况记为步骤失败：

- `system-tools` 输出行首的 `FATAL:`、`VERIFY_FAILED:`、`FILE_TAMPER_FAILED:`、`ERROR:`，以及 `UPLOAD_RESULT: check…`。
- DVWA 初始化输出 `DVWA ready (..., login_ok: 0)`。
- `curl` 或调用 curl 的 shell 步骤返回常见 HTML 错误页，或者打印 curl 传输错误；携带 Cookie 的请求返回含密码输入框的登录表单。

HTTP 页面检查只应用于 HTTP 命令。普通文件输出不据此判失败；未携带 Cookie 的登录页发现请求，以及明确请求登录入口的 curl 命令，也不因表单本身失败。带有用户名和密码字段的资料编辑或修改密码表单，不因这些字段本身被当作登录页。页面检查依据工具实际返回的文本，并非完整的 HTTP 状态码协议；空正文、自定义错误页或已截断输出仍可能需要预案自身的明确验证信号。

失败结果同步写入步骤、尝试记录、证据及审计，不触发成功规则对应的 MITRE 命中。机械执行遇到非可选失败步骤继续遵循停止策略；可选步骤失败可以继续。运行总状态仍遵循现有 `execution_finished` 约定：`COMPLETED` 表示流程结束，不能据此认定利用成功，应检查步骤结果和评分证据。历史运行不重判，也不需要数据库迁移。

在 `backend/` 运行针对性验证：

```sh
node --experimental-test-module-mocks --test test/execution-contracts.test.js test/execution-session.test.js test/execution-state.test.js test/web-scan-runner.test.js
```

回归通过内存数据库与模拟容器调用验证同次运行的文件传递、并发隔离、重复执行拒绝、重试、异常/中止清理、业务失败落库和预案不变。测试不会执行真实上传或篡改，也不代表已完成靶场联调。
