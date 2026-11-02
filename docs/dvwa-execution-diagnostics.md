# DVWA 首页修改预案的执行诊断

任务页顶部使用“待核对”表达异常结束，不自动展示整段失败横幅。扫描异常的详细信息保留在进度悬浮说明、扫描任务和过程日志中；结果页顶部不展开内部停止原因，悬浮说明与工具结果仍保留真实状态。返回步骤数与证据数不等于利用成功，不修改后台状态或历史结果。

`DVWA File Tampering Attack Chain` 需要登录会话能够延续到上传步骤，上传入口允许 PHP 文件，上传目录和实际首页文件可写；最后还须从 HTTP 首页确认修改标记。预案返回全部步骤并不保证这些条件都成立。

如果上传返回登录页、访问载荷返回 404，先检查 Cookie 是否传递，不能直接认定靶场权限不正确。修复前的执行器通过独立的 `run --rm` 工具容器执行命令；普通输出目录有共享挂载，但容器 `/tmp` 本身不共享。旧预案将 Cookie 写入 `/tmp/dvwa_jar.txt`，后续容器无法直接读取前一步的该文件。这属于执行环境的会话连续性问题；放宽靶场文件权限无法恢复丢失的 Cookie。

只读检查可核对容器是否只读、DVWA 默认安全等级、PHP 上传开关，以及实际 Web 服务用户对上传目录和首页的写权限。不要输出整个配置文件或会话内容；确认实际会话安全等级时也不能只依据默认配置。

最初的诊断仅调整前端提示并检查执行记录。后续执行器已增加按运行隔离的跨容器 `/tmp` 挂载，并修正退出码为 0 的部分业务失败判定，详见[执行器跨步骤会话与结果判定](executor-session-results.md)。旧预案、靶场配置与历史记录保持原样；前后端修复均需加载更新后的程序才会生效。

初次诊断时的验证记录（仓库根目录，后端测试除外；当前执行器回归见上述链接）：

- `cmake --build build --target RedTeam-Platform RedTeam-Platform-Batch16Checks -j 4`：编译通过。
- `QT_QPA_PLATFORM=offscreen REDTEAM_SCAN_PRESENTATION_ONLY=1 build/frontend/RedTeam-Platform-Batch16Checks`：104 项通过。
- `QT_QPA_PLATFORM=offscreen REDTEAM_HANDOFF_ONLY=1 build/frontend/RedTeam-Platform-Batch16Checks`：434 项通过，包含简洁状态、真实原因可达性与原结果计数检查。
- 在 `backend/` 运行 `npm test`：765 项通过、3 项跳过、0 失败。
