# 选择目标主机的源码文件夹

任务创建页与独立源码扫描页默认选择“选择目标主机的源码文件夹”。填写目标主机地址，点击“选择目标文件夹”，读取目录、双击进入子目录，再确认“选择当前文件夹”。切换目标会清除旧选择。这里浏览的是目标服务返回的目录，不使用客户端本机文件选择器，也不要求用户填写 CScan 的 `/src` 路径。

支持两种访问方式：

- HTTP：读取与目标同协议、主机、端口的目录索引。可输入任意实际开放的目录，例如 `/project/code/`，没有写死 `/source`。普通网页不等于文件系统；没有目录索引的主机应使用 SSH 连接。
- SSH：使用后端已有 `data/source-scan/connections.json`（或 `SOURCE_SCAN_CONNECTIONS_FILE`）中的连接。下拉框只列出绑定当前目标的 SSH 连接；从配置的 `source_root` 开始浏览，选择该目录或子目录。认证文件、SSH 主机指纹由后端配置，客户端不接收或存储密钥。

SSH 连接仍使用已有字段 `id`、`kind=ssh`、`targets`、`host`、`username`、`port`、`source_root`，以及 `identity_file` 或 `password_file`。`targets` 应填写与界面一致的完整目标地址。未配置 SSH 连接时不会假装能浏览主机磁盘，也不会自动关闭主机指纹验证。

## 接口与执行

`POST /api/scan-tasks/source-directory` 接收：

```json
{"target":"http://192.0.2.40:8089/","connection_id":"project","source_subdir":"module"}
```

`source_subdir` 是相对已配置根目录的路径，空字符串表示根目录。返回当前路径、上级路径和最多 500 个子文件夹；拒绝 `..`、绝对路径和符号链接目录。HTTP 方式使用已有 `source_url` 参数。

创建扫描时提交 `input_kind=remote_directory`，以及 `connection_id` / `source_subdir` 或 `source_url`。任务工作台在 `config` 中使用 `source_connection_id`，其余字段相同。工作台保持所选目录并只创建源码子扫描，不自动添加端口或网站扫描。

平台复用已有源码采集与快照链路，将所选目录的 C/C++ 文件交付到 CScan 独立目录，再调用远端扫描。沿用 500 个文件、单文件 512 KiB、总计 8 MiB 的上限和跳过记录；不执行或编译所选源码。扫描执行时再次核对目录范围，不以浏览结果替代实际权限检查。目录选择不证明存在可执行攻击测试入口。

原始快照任务、HTTP 参数任务以及高级直接提交任务保持兼容。新任务仍遵守原来的重复提交、取消及重启恢复逻辑。

扫描提交、任务与子任务进度查询、报告获取均使用独立 CScan 服务的 API，不需要部署或调用 PentAGI。界面显示已完成任务和子任务数量；这些数量不等同于已审阅源码的比例。报告按现有校验规则导入，只有任务成功且报告覆盖检查通过才标记完成。连续三次查询均处于等待状态且没有任务时，平台明确报告启动失败，避免一直显示扫描中。

自动化联调使用模拟 CScan 服务，覆盖所选 HTTP 目录的采集、快照交付、任务提交、进度和报告保存。它不能替代真实 CScan 模型与工具执行的验收。

验证：`cd backend && npm run test:source`；使用现有 CMake 构建 `RedTeam-Platform` 和 `RedTeam-Platform-Batch16Checks`，运行 `ctest --test-dir build -R ui-context --output-on-failure`。
