# 直接调用 CScan 的源码扫描流程

> 默认入口为“源码路径／地址（CScan 自行读取）”。也可浏览目标目录后提交位置，见 [源码位置选择](remote-source-folder.md)。两种方式都不上传文件、不创建快照或挂载。

源码扫描参考 `/home/zxf/code/pentagi-v3` 中的实际调用逻辑：在扫描弹窗指定目标、审计要求，通过 GraphQL `createFlow` 提交给服务，轮询任务和子任务，读取 `tasks.result` 报告，再解析为漏洞列表。

参考客户端当前将源码和 Web 扫描放在同一业务入口。本项目源码任务使用独立 CScan 的地址、认证和 Flow；报告在全部任务成功结束后统一解析和导入，不引入客户端混合扫描入口或其后续攻击实现。

接口契约已对照服务部署中的 `/home/aistation/apps/cscan-agent/backend/pkg/server/docs/swagger.yaml` 和 `/home/aistation/apps/cscan-agent/backend/pkg/graph/schema.graphqls`：Swagger 明确列出 `/api/v1/graphql`；REST 对应创建接口为 `POST /flows/`（`provider`、`input`），结果为 `GET /flows/{flowID}/tasks/`、`subtasks/` 的 `result`，结束操作为 `PUT /flows/{flowID}` 的 `finish` action。这里沿用参考客户端的 GraphQL 调用，不要求另建上传接口或固定 JSON 文件。

平台只提交源码位置和审计要求，不下载源码，不以平台快照或共享报告文件作为前置条件。CScan 复用 PentAGI 的执行框架但独立运行，平台不把扫描任务转交原 PentAGI 服务。

部署侧应将 `DOCKER_SOURCE_DIR` 置空，不向 worker 绑定共享源码目录，也不要求 `CSCAN_SOURCE_DIR`。已有 worker 的挂载配置不能在线修改，应在原任务结束后移除旧容器；保留任务数据和 `/work` 执行输出。历史任务、记忆召回或旧源码目录只可提供线索，不能替代本次目标，Agent 必须重新核实源码来源。

## 操作

1. 新建任务选择“源码扫描（CScan） / 程序测试”，默认输入“源码路径／地址（CScan 自行读取）”；独立扫描页使用相同入口。
2. 测试目标填写靶机 IP、主机:端口、HTTP/TCP 地址，例如 `http://192.168.1.113:8089/`。不需要选择本机文件夹，也不要求源码预先位于 `/src`。
3. 在审计说明中补充靶机上的源码位置、已有授权连接的说明和关注问题。目标和要求一并传给远端 CScan Flow，由它使用既有工具和访问条件核实并读取源码。只有站点响应或二进制不等于取得源码，无法访问时必须报告缺少的条件。
4. 如果已知源码就在远端执行环境可访问的目录，也可直接以 `/var/www/project` 等明确绝对路径作为目标。这不是客户端路径，不上传本机文件，不限定 `/src` 前缀。纯路径任务只提交 CScan，不附带网络扫描。
5. 创建并启动任务，查看 Flow、任务/子任务报告和候选漏洞。网络目标保留独立的原目标端口及拓扑探测，邻居仍仅用于拓扑；后续攻击验证需单独确认。

界面不再弹出本机文件选择器。另有程序运行入口时，可填写可选的验证运行入口；纯路径任务缺少运行入口时，F08 继续显示缺失条件。原有“程序运行入口”模式仍使用平台动态测试流程。

## 调用与报告

```text
靶机目标 / 远端源码路径 + 审计要求
  → createFlow(modelProvider, input)
  → flow + tasks/subtasks 状态
  → 收齐 tasks.result 与 subtasks.result，先保存完整原文
  → finishFlow
  → 统一解析、校验、去重，事务导入漏洞
  → 标记平台任务完成／部分完成
  → 现有预案／逐漏洞验证
```

CScan 的 `waiting` 不一定是失败。平台核对扫描任务和子任务是否完成；失败或等待人工输入明确显示原因，不自动重复创建 Flow。取得任务报告后结束本次 Flow。取消、请求超时、重启恢复仍保留原 Flow 的对应关系。

若连续三次查询都返回 `waiting` 且任务列表为空，平台报告“未创建扫描任务”，并请求停止原 Flow，不再等待整个扫描超时，也不自动重提。短暂的初始空列表允许继续等待；恢复到运行状态会重新计数。此情况可能发生于 CScan 调用模型生成任务标题失败，应检查 CScan 服务端日志及模型连接。

所有扫描任务结束后，报告已有明确字段时直接提取；普通文字报告调用平台已配置的模型统一整理结果。这个模型只接收报告，不读取或扫描源代码。解析失败时保留完整原文并标记缺口，不以本地源码扫描兜底。文件和依据必须出现在原始报告中，不接受解析模型新增的证据。

### 统一解析、导入与源码字段适配

- 扫描期间持续轮询任务和子任务，保存已返回的原始报告及来源 ID，展示任务完成数量；不调用报告解析模型、不生成 `source_finding`。任务失败、取消、超时或等待人工输入时保留已收到的原文，不能把部分扫描当成完整扫描。
- Flow 进入 `waiting` 或 `finished` 后仍须核对所有任务及子任务均为 `finished`；收齐父任务和子任务报告后先保存完整原文，再结束远端 Flow，随后统一解析。只有最终摘要而忽略子任务会丢失证据，因此两者一起处理。
- 平台任务在解析、导入阶段保持 `RUNNING`，覆盖记录的 `cscan.state` 分别为 `parsing`、`importing`，界面显示“正在解析报告”“正在导入漏洞”。处理结束后才转为 `COMPLETED`／`PARTIAL` 并开放漏洞选择、预案生成。解析与导入缺口明确记录，原文持续保留。
- 保持 `source_finding` 的 `title/file/start_line/end_line/reason/severity/cwe/preconditions/suggestion` 字段不变。兼容模型返回的 `vulnerabilities[].name/evidence`，仍要求明确源码文件、行号及报告原文依据；URL 不能充当源文件。
- 有标题分段的混合报告分别解析，重复的相同分段只处理一次；字段明确时直接提取，必要时才调用平台模型整理原报告。文件和依据必须出现在报告中。
- 模型返回数组中的个别无效项记录为解析缺口，仍保留同批有效发现。操作员取消会立即传递给报告解析器，取消后迟到的模型结果不会导入；任务仍等待正在执行的调用结束后才释放重试限制。
- 相同文件、起始行及 CWE（缺少时使用标题）的发现合并，保留 `source_task_ids`、`source_subtask_ids`、`report_evidence` 和 `analyses`。漏洞集中在一个 SQLite 事务内导入，保存异常时整批回滚，完整报告不回滚。
- 最终报告声明无法访问源码时，不导入源码漏洞；历史已有候选保留记录 ID 和验证引用，转为信息记录。后续验证只使用单独声明且在范围内的 `runtime_target`，源码目录或源码 HTTP 地址不自动成为验证入口。

### 从已保存报告重试

扫描已经成功结束但报告解析／导入失败时，详情返回 `can_reparse_report=true`，源码扫描的重试按钮显示“重新解析报告”。`POST /api/scan-tasks/:scanTaskId/reparse` 使用本任务已保存的完整报告重新解析和导入，不读取源码、不创建 Flow、不调用远端扫描 API，也不创建新的扫描任务。操作继承源码任务访问权限；没有完整报告或任务仍在运行时返回 409。

重复解析按相同去重键更新已有漏洞，保留记录 ID、来源证据和验证引用，不重复插入相同漏洞。重试沿用原扫描开始时间，更新本次报告处理结束时间；旧原文和错误记录继续保留。原 Flow 的结束／停止未确认仍作为处理缺口保留，重新解析不代表已经核实远端退出。旧快照导入链路不使用此入口；原生旧任务如已保存完整 `task_result` 报告，可复用报告重试。

扫描没有成功结束、仅收到部分子任务报告时，不能用重新解析代替完整扫描，需新建扫描任务。进度和原文持久化不改变重启策略：重启仍收束未结束 Flow、标记中断，不自动重扫；已保存完整报告的任务可手动重新解析。没有新增数据库迁移，阶段和报告标记使用现有 JSON 字段。

平台没有读取源码，因此不会伪造源码哈希、快照、代码片段或“已校验源码行号”。发现明确记录 `evidence_origin=cscan_report`、`source_location_verified=false`、`source_version_verified=false`、`runtime_verified=false`；报告中的定位和运行效果仍需复核。`cscan_complete` 表示该次服务任务／报告处理完成，`whole_project_complete=false` 不代表整个项目都已审阅或无漏洞。

## 配置

平台后端需要 CScan API 地址和服务凭据：

```sh
CSCAN_API_URL=http://127.0.0.1:18080
CSCAN_TOKEN_FILE=/path/to/existing/cscan-token
CSCAN_PROVIDER=custom
```

新流程无需平台配置 `CSCAN_SOURCES_DIR`、`CSCAN_WORK_DIR`，也无需平台与 CScan 共享目录。平台提交目标与要求；源码访问使用远端已有连接和工具，不能仅凭目标地址认定已经读取源码，不新增上传接口。创建 Flow 的超时单独使用 `CSCAN_CREATE_TIMEOUT_MS`（默认五分钟），参考客户端对 worker 冷启动的等待设置；查询和停止请求沿用有界的短超时。

扫描等待与后续报告解析分别受 `CSCAN_TIMEOUT_MS` 限制，默认各三十分钟；手动重新解析也使用该期限。报告收齐后先结束远端 Flow，再进入平台解析阶段。

默认环境检查也直接检查凭据和 API，不再要求共享源码／报告目录、Python 或 SSH：

```sh
cd backend
npm run check:source-env -- --api --source-path /src/my-project
```

此命令只验证配置、路径格式和认证，不创建 Flow，目录是否存在由 CScan 执行扫描时确认。旧 `--source-kind http|local|ssh` 只用于历史采集链路的排查。

测评入口同样直接调用服务。先由服务维护方将仓库中的六个受控样例放入对应挂载目录，再运行 `npm run benchmark:source -- --source-path /src/benchmark --output /tmp/cscan-benchmark.json`。脚本不上传或快照待扫源码；可选 `--diagnostics` 只针对本机仓库固定样例作 ASan/UBSan 对照，不代表已验证远端部署版本。

API 创建参数示例：

```json
{
  "target": "http://192.168.1.113:8089/",
  "scan_type": "source_scan",
  "parameters": {
    "input_kind": "agent",
    "cscan_target": "http://192.168.1.113:8089/",
    "source_notes": "源码位于靶机 /var/www/project，使用既有授权连接，关注输入长度检查"
  }
}
```

任务工作台在 `config` 中使用相同的 `cscan_target`、`source_notes`、`input_kind` 和可选 `runtime_target`。`input_kind=agent` 时省略 `cscan_target` 会采用测试目标。结构化范围及排除项一起传给远端 Flow；独立指定的源码目标和运行入口都必须纳入范围。路径不能交给网络扫描器。

报告要求明确输出 `Source-Access: available|unavailable|unknown` 及源码访问依据/缺失条件。服务报告源码不可访问时保留原报告、标记扫描失败且不保存源码漏洞候选；未明确确认源码访问时保留有报告引用的候选并标记未完成，不宣称已完成源码审计。访问状态是远端报告的声明，平台仍保留源码定位、版本和运行效果未经独立验证的标记。

## 历史兼容与验证

已存在的旧快照任务保留原始证据和读取方式。新建直接提交使用 `cscan_target`，目录选择使用 `remote_directory`，二者均走原生服务调用，不退回旧采集链路。旧记录中真实存在的快照与哈希不删除。

执行 `cd backend && npm run test:source`。`test/cscan-native.test.js` 使用真实 HTTP GraphQL 测试服务，核实不接触本机源码/共享文件、提交靶机目标或远端路径与要求、处理 waiting 状态、读取任务报告、解析失败保留原文、范围与重复执行、工作台只产生一个源码子扫描，以及发现进入 F08 后缺少运行入口不能直接执行。协议回归不代表真实 CScan 模型质量验收。
