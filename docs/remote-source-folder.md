# CScan 源码位置选择与直接调用

默认输入为“源码路径／地址（CScan 自行读取）”。填写执行侧源码路径或局域网源码地址，附带审计要求，通过 createFlow(modelProvider,input) 交给独立 CScan。平台不替 Agent 读取源文件，不上传、生成快照或创建挂载。进度与报告使用任务/子任务 API，包括 tasks.result。

可选的“选择目标主机的源码文件夹”只帮助选择位置：

- HTTP：读取同源目录索引，选择后向 CScan 提交源码 URL，不下载目录内文件。
- SSH：使用后端已配置连接浏览目录，选择后向 CScan 提交目标主机、源码绝对路径及 SSH 端口说明。不传递平台密钥或密码，不假定 Agent 自动继承平台连接权限。
- 目录浏览成功不等于 CScan 可访问。Agent 必须自行核实读取条件；不可访问时展示其报告，不能回退到平台上传，也不能标记扫描成功。

目录浏览仍使用 /api/scan-tasks/source-directory。选择提交参数保持 input_kind=remote_directory 与 connection_id/source_subdir 或 source_url 兼容，执行时转换成位置说明，走原生 CScan 调用。手工输入路径或地址不要求配置目录浏览连接。

参考 pentagi-v3：createFlow 接收任务文本，不包含源码上传；客户端从任务结果获取报告。CScan 当前部署已有 /src 只读挂载，这是服务端现有执行环境，平台不把它规定为所有输入的必经步骤，也不会新建挂载。

保留旧快照任务和证据的兼容代码，但新 agent/remote_directory 任务不走旧采集路径。不能用任务完成或 Agent 的报告推断整个项目全部覆盖；whole_project_complete 保持 false。

验证：npm run test:source；现有 CMake 编译主程序和 Batch16Checks；ctest --test-dir build -R ui-context --output-on-failure。检查包括路径和地址转发、无快照采集、无凭据转发、原生任务报告、Source-Access unavailable 错误路径及 UI 默认入口。
