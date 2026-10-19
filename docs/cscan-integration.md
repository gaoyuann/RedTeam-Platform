# CScan 源码扫描接入

源码扫描统一由独立 CScan 服务执行。任务中的 `source_scan`、独立扫描页中提供了源码的 `program_scan`、源码测评脚本均调用 CScan。平台不再运行原来的 cppcheck / Flawfinder 加本地 AI 源码审计流程，也没有失败后切回旧引擎的开关。未提供源码的远程程序测试仍沿用原程序测试功能。

## 调用链路

```text
HTTP / SSH / 本机源码目录
  → 冻结 C/C++ 快照、记录文件哈希
  → 交付到 CScan 共享源码目录下的独立任务目录
  → GraphQL createFlow(custom, input)
  → 查询 flow 状态
  → 核对 task/subtask 完成状态
  → 读取 findings.json / report.md / tasks.result
  → finishFlow 结束本次 Flow 并释放 worker
  → 校验快照版本、文件和行号
  → source_finding → 现有漏洞选择、预案、审批与执行
```

源码交付和快照属于输入准备，扫描和 Agent 分析由 CScan 完成。旧客户端提交的 `ai_analysis` / `ai_batches` 不再控制扫描，新界面已撤下这些选项。平台扫描模型没有配置时，提供了源码的任务仍可完成 CScan 调用；后续生成预案仍需要平台原有模型配置。

## 后端环境

第一版适用于平台后端与 CScan 工作目录处于同一主机，或使用相同的共享文件系统。103 上的平台后端可直接访问 CScan 的回环地址。仅转发 API 端口不能替代源码和报告目录共享；当前不假定 CScan 存在源码上传或报告下载接口。

在**平台后端进程的环境**中设置（不要把凭据内容放进代码或仓库）：

```sh
export CSCAN_API_URL=http://127.0.0.1:18080
export CSCAN_TOKEN_FILE=/path/to/cscan-token-file
export CSCAN_SOURCES_DIR=/home/aistation/apps/cscan-agent/workspace/sources
export CSCAN_WORK_DIR=/home/aistation/apps/cscan-agent/workspace/work
export CSCAN_PROVIDER=custom
```

`CSCAN_TOKEN_FILE` 指向服务维护方提供的凭据文件。也支持进程环境 `CSCAN_API_TOKEN`，优先于文件。客户端不返回或记录凭据。`CSCAN_HOME` 可统一修改工作目录的默认根路径，默认 `/home/aistation/apps/cscan-agent`。运行服务的账户须能读取凭据、创建源码子目录和读取报告；不要为接入开放公网监听或修改 Docker Socket 权限。

后端以排他创建方式生成独立源码目录，按冻结快照的 UTF-8 内容重新计算哈希后交付。worker 中的路径为 `/src/rt-<随机标识>`。目录可遍历，源码文件只读；源码根目录的上层权限仍由部署环境控制。CScan 必须将配置的源码根目录以只读方式挂载到 worker 的 `/src`，并将每个 Flow 的独立工作目录挂载到 `/work`。

可调节超时：`CSCAN_TIMEOUT_MS` 默认 30 分钟（包括源码交付和扫描），`CSCAN_REQUEST_TIMEOUT_MS` 默认 15 秒，`CSCAN_POLL_MS` 默认 3 秒。后端不自动加载任意 `.env`；应通过原启动脚本或服务的环境文件注入这些配置。

执行只读环境检查：

```sh
cd backend
npm run check:source-env -- --source-kind http --api
```

自检检查账户目录权限、凭据是否可读，并通过 GraphQL 验证认证；不会创建 Flow、运行扫描或修改配置。`local` 来源另检查 Python，`ssh` 来源另检查 SSH 客户端。旧 `rt-sast-c` 镜像不再是源码扫描前置条件。

## 结果协议

已对照公开仓库提交 `b08c9ecea8858c0a7b54aba1d9e913de607ed1f9` 的 [提交脚本](https://github.com/drinkflower/cscan/blob/b08c9ecea8858c0a7b54aba1d9e913de607ed1f9/submit-cscan.sh)、[任务状态实现](https://github.com/drinkflower/cscan/blob/b08c9ecea8858c0a7b54aba1d9e913de607ed1f9/backend/pkg/controller/task.go)、GraphQL schema 和 worker 挂载实现。原生服务要求 Markdown 报告，同时将任务结果保存在 `tasks.result`；没有固定的结构化漏洞接口。适配器在任务说明中额外请求 JSON 结果，但不以模型遵守这一约定作为唯一接入路径：

- 优先读取 `/work/findings.json`，最多 2 MiB；宿主机对应 `CSCAN_WORK_DIR/flow-<Flow ID>/findings.json`。这是平台提出的扩展结果约定。
- JSON 文件不存在时读取原生 `/work/report.md`；文件也未生成时，通过 GraphQL `tasks(flowId).result` 读取数据库中的任务报告。
- JSON 已存在但格式或版本错误时，明确报错，不以 Markdown 掩盖错误。所有原始可用报告均保留。

```json
{
  "snapshot_id": "必须原样复制任务中给出的快照ID",
  "findings": [
    {
      "file": "src/input.c",
      "start_line": 12,
      "end_line": 12,
      "title": "输入长度检查不足",
      "severity": "high",
      "cwe": "CWE-120",
      "reason": "基于实际代码的根因与影响依据",
      "preconditions": "输入可控性、可达性及未知条件",
      "suggestion": "修复建议"
    }
  ],
  "coverage": {
    "reviewed_files": ["src/input.c"],
    "omitted_files": [],
    "complete": true
  }
}
```

无发现时返回空 `findings`，覆盖清单仍需填写。发现主定位最多 41 行；文件路径相对本次输入目录，也支持本次 `/src/rt-<标识>/` 前缀。可选 `trace` 和 `assessment` 沿用平台源码证据格式，所有引用均校验实际快照。平台自己提取代码和哈希，不信任外部报告自带的代码片段或“已经验证”结论。

Markdown 仅解析具有明确名称、文件、行号和依据的字段块或表格，不从自由文字推断漏洞；代码块不作为报告字段执行或消费。任务说明建议每项报告使用 `## 标题` 及 `File:`、`Line:`、`Severity:`、`CWE:`、`Evidence:`、`Preconditions:`、`Remediation:` 字段。Markdown 没有逐文件覆盖清单，因此保留原文和已校验的发现，同时标记覆盖不足；不能把未解析到发现当成已证明没有漏洞。

格式、版本或报告读取失败会留下错误记录，不会回退到本地扫描。个别发现定位无效时拒绝该条、保留其余发现并标记覆盖不足。`source_coverage.cscan_complete` 仅表示服务报告与本次快照清单核对完整，不代表源码漏洞已经运行验证。

## 状态与重复提交

Flow 的 `created` / `running` 保持扫描中。原生 `task.SetStatus` 在任务 `finished` 和 `failed` 两种情况下都会将 Flow 设为 `waiting`，因此不能只看 Flow 是否 `finished`，也不能把所有 `waiting` 判成失败。平台查询同一 Flow 下的任务和子任务：全部 `finished` 才读取报告，任何 `failed` 均报错，任务/子任务 `waiting` 则明确需要输入；没有任务或仍有 `running` 时继续等待。即使 Flow 被外部提前结束，也必须通过任务成功状态检查。

报告取得后，对仍处于 `waiting` 的本次 Flow 调用 `finishFlow`；服务端会结束 Flow 并释放主要 worker。结束请求失败时保留已取得报告，标记结束未确认、任务部分完成；平台重启后再尝试结束，不重复扫描。平台记录 Flow ID、任务目录、错误和停止/结束确认状态。

同一进程的重复调用共享一次提交，已留有源码审计记录的任务不重新创建 Flow。创建请求超时时，远端可能已经接受，平台记录 `submission_uncertain`，不自动重试。操作员取消或扫描超时时，对已知 Flow 调用 `stopFlow`，使用独立请求期限，并明确记录停止是否得到应答。

服务重启时停止已记录的未结束 Flow，并将原任务标为失败，保留旧快照和证据；无法连接 CScan 时显示停止未确认。没有收到 Flow ID 的不确定提交只能由维护方核对服务端记录，不盲目重建。新扫描应创建新平台任务。`stopFlow` 返回成功代表服务接收停止操作，不能代替 worker 容器退出核验。

## 输入范围与验收

本次替换扫描引擎，现有输入采集限制继续明确记录：最多 500 个 C/C++ 文件、单文件 512 KiB、合计 8 MiB；本机/SSH 来源排除 `.git`、`node_modules`、`vendor`、`build`、`dist`、`.cache`，不跟随符号链接。HTTP 来源受目录索引和同源规则限制。这不是完整项目归档接口，`whole_project_complete` 始终为 false；只交付这些文件不能声称整个仓库都已扫描。

执行 `npm run test:source`，包含真实 HTTP GraphQL 协议、原生“任务完成但 Flow waiting”状态、Markdown/数据库报告导入、finishFlow、超时、取消、重启、重复提交、无效引用和任务预案/审批/HTTP/TCP 执行的隔离回归。测试服务返回受控发现，不调用真实 CScan 模型，不能作为其检出率结论。`npm run benchmark:source -- --output /tmp/cscan-benchmark.json` 则会实际创建 CScan Flow 扫描仓库中的六个固定对照样例，须在具有上述共享目录和服务配置的环境执行。

真实服务仍须验收：worker 挂载路径、模型调用、JSON 结果约定、报告权限、Flow 最终状态和停止效果。实现与本地协议回归通过不代表 103 上已经部署或完成真实扫描。
