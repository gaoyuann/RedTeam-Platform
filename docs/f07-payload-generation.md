# F07 漏洞载荷生成与复用

## 当前流程

扫描结果中的漏洞记录有稳定的 `scan_results.id`。在扫描结果上选择“查找或生成此漏洞载荷”后，客户端调用 `POST /api/payloads/resolve`，请求体为 `{ "finding_id": 123 }`。服务端先检查记录类型和任务归属，再从脱敏后的发现字段构造漏洞签名。相同漏洞标识、位置、产品版本和目标类型命中已保存的结构化载荷时，返回 `state: "existing"`；否则调用平台配置的大模型，校验结果后保存并返回 `state: "generated"`。模型失败或结构校验失败时返回错误，不保存无法消费的载荷。同一进程内同一签名的并发请求共用一次生成。命中或生成后会使用 F06 的版本与关联接口保存漏洞和载荷的关系，响应返回 `catalog_version`。

生成结果保存于既有 `generated_payloads` 表，来源为 `ai_generated`，状态为 `accepted`，不需要人工审核。旧候选记录仍可由管理员通过原有审核接口处理。SQL 注入等已知类别会将同类静态 Payloader 样本提供给模型作参考；预览中列出的静态参考样本来自 F06 的具体漏洞匹配结果。其中的展示命令不是结构化工具参数，不能仅凭分类名称自动执行。

## 载荷契约

可自动消费的生成载荷包含 `id`、`version`、`source`、`applicability.signature`、`consumption: { type: "tool_args", tool_id, args_template }` 和 `validation`。参数必须是字符串数组，包含 `<target>`，工具须在生成白名单中。通用 HTTP 输入和 TCP 交互采用平台已有的有界 `target-request` 请求格式，并在入库前解析校验。执行编译器校验步骤工具与载荷工具一致，将参数数组用于目标替换和运行时范围检查。旧预案的 `payload_id` 仍可用于载荷知识展示；不会把静态样本的显示命令拆成可执行参数。

载荷详情的 `verification_history` 仅展示当前用户自己可见的执行证据，管理员可查看全部；其中 `tool_success` 只代表工具调用结果，不代表漏洞验证成立。运行证据另外保留载荷 ID、版本、来源和消费方式。新生成的 `validation.runtime_verified: false` 表示生成时尚未进行实际验证。

## 验证边界

模型输出的结构校验可以阻止缺少工具、目标变量或参数数组的结果进入可复用库，但不能证明目标存在漏洞，也不能保证工具在特定环境中成功。F08 仍需把载荷绑定到具体 Playbook 步骤，执行并用证据判定结果。本次未启动靶场工具或向目标发送验证请求；实际消费与成功判据需在 F08 联调时复验。

HexStrike-AI 是项目的开发来源之一；当前载荷生成调用本项目的 `llmClient`，执行由本项目的 `executionEngine` 和 `toolRunner` 组织，未发现必须依赖独立 HexStrike 服务的运行时路径。详见[项目来源与 HexStrike-AI 的关系](项目来源与HexStrike关系.md)。
