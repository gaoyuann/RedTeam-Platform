# ReAct 推理引擎迁移方案

> 日期：2026-07-29 | 状态：设计评审中

## Context

重构后的 RedTeam-Platform 丢失了原项目最核心的 **ReAct（Reasoning + Acting）执行引擎**。当前 `executionEngine.js` 只是机械式地逐步骤执行 Playbook，LLM 不参与执行过程中的分析、思考和调整。原项目中 LLM 在每一步执行后都会被调用，输出 `Observation/Thought/Action`，能够动态调整攻击计划。

**目标**：将原项目的 ReAct 能力迁移到重构项目中，同时保持与现有 SQLite 数据库和容器化工具体系的兼容。

---

## 设计原则

1. **渐进增强，而非替换**：保留当前机械执行模式作为 LLM 不可用时的 fallback
2. **数据库持久化**：原项目全内存状态，重构项目用 SQLite，ReAct 状态必须持久化
3. **复用现有基础设施**：`llmClient.js`、`toolRunner.js`、`containerEngine.js` 不重写
4. **KG 数据已就位**：`data/knowledge/kg_full.json`（5.7MB）和 `technique_zh.json` 已存在

---

## 架构总览

```
                    ┌─────────────────────────────┐
                    │   executionEngine.js (改造)  │
                    │   executeRun(runId, config)  │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │  config.engine = 'react' ?  │
                    └──┬─────────────────────┬───┘
                       │ YES                 │ NO
          ┌────────────▼──────┐  ┌──────────▼──────────┐
          │  reactEngine.js   │  │  当前机械执行逻辑   │
          │  (LLM-in-the-loop)│  │  (逐步骤 runTool)   │
          └───────────────────┘  └─────────────────────┘
```

---

## 新增/修改文件清单

### 新增文件

| 文件 | 行数估计 | 说明 |
|------|---------|------|
| `backend/src/services/reactEngine.js` | ~350 | ReAct 循环核心：prompt 构建、Action 解析、动态步骤管理 |
| `backend/src/services/knowledgeEnricher.js` | ~200 | 从 KG 构建步骤上下文（移植自 `runtimeKnowledgeEnricher.js`） |
| `backend/src/services/evidenceSerializer.js` | ~80 | 证据历史序列化（移植自 `evidenceSerializer.js`） |
| `backend/src/db/migrations/006_add_react_columns.js` | ~30 | 数据库迁移：ReAct 状态列 |

### 修改文件

| 文件 | 改动说明 |
|------|---------|
| `backend/src/services/executionEngine.js` | 增加 ReAct 模式分支，每步执行后调用 reactEngine |
| `backend/src/services/llmClient.js` | 增加 `callLlmReact()` 方法：永不 reject 的安全调用 |
| `backend/src/services/playbookGenerator.js` | 增强 prompt：注入 KG 上下文 + Payloader 载荷信息 |
| `backend/src/routes/runs.js` | 新增 `GET /api/runs/:runId/react-state` 端点 |
| `frontend/src/SimpleMainWindow.cpp` | 执行进度区显示 LLM 的 Thought/Action 文本 |
| `frontend/src/SimpleMainWindow.h` | 新增 ReAct 状态显示相关成员 |

---

## 核心模块设计

### 1. `reactEngine.js` — ReAct 循环引擎

```js
// 主入口：每步执行后调用
export async function reactDecide({ runId, stepIndex, toolId, stepResult, 
                                     evidenceHistory, remainingSteps, target, 
                                     kgContext, aiConfig }) 
  → { action: 'continue'|'adjust'|'insert'|'stop',
      thought: string,      // LLM 的分析
      observation: string,  // LLM 对结果的总结
      adjustArgs?,          // adjust 时的修改参数
      insertStep?,          // insert 时的新步骤
      stopReason? }         // stop 时的终止原因
```

**ReAct Prompt 结构**（移植自原项目，简化）：

```
你是渗透测试执行代理，当前运行在 Auto-pilot 模式。

## 当前执行状态
- 目标: {target}
- 已完成: {completedSteps}/{totalSteps} 步
- 当前步骤: step{idx} {toolId} — {stepName}

## 执行证据历史
{serializeEvidenceHistory(evidenceHistory)}

## 剩余计划
{serializeCurrentPlan(remainingSteps)}

## KG 知识上下文
{kgContext}

输出格式：
Observation: <中文总结最新步骤结果>
Thought: <中文分析计划是否有效、下一步做什么>
Action: <action type="continue|adjust|insert|stop" ... />
```

**Action 解析**：

| Action | 属性 | 行为 |
|--------|------|------|
| `continue` | 无 | 按计划执行下一步 |
| `adjust` | `toolId`, `newArgs`, `stepIndex` | 修改指定步骤的参数后继续 |
| `insert` | `toolId`, `args`, `position="after"` | 在当前位置后插入新步骤 |
| `stop` | `reason`, `finalSummary` | 终止运行并记录原因 |

**安全阀**：
- ReAct 调用上限：30 次/运行（超出后自动 continue）
- LLM 返回无效 Action → 默认 continue
- LLM 调用失败/超时 → 默认 continue（绝不挂死）
- `adjust`/`insert` 需校验 toolId 在 `IMAGE_MAP` 中存在

### 2. `knowledgeEnricher.js` — KG 运行时上下文

```js
// 懒加载 KG 数据
loadKnowledgeIndex()    // data/knowledge/knowledge_index.json
loadKgFull()            // data/knowledge/kg_full.json  
loadTechniqueZh()       // data/knowledge/technique_zh.json

// 主入口：为 ReAct prompt 构建 KG 上下文
export function buildKGContextForStep(toolId, payloadData)
  → string  // 注入到 ReAct prompt 中

// 攻击链推荐
export function getSuggestedNextTools(toolId)
  → { current, next_techniques, suggested_tools }
```

**数据源**：直接读取 `data/knowledge/` 下已有的 JSON 文件，无需数据库。

### 3. `evidenceSerializer.js` — 证据序列化

```js
// 将证据历史序列化为 ReAct prompt 文本
export function serializeEvidenceHistory(history)
  → string  // 格式: "步骤0 [nmap]: 发现80端口开放\n步骤1 [nuclei]: 发现XSS漏洞..."

// 将剩余计划序列化
export function serializeCurrentPlan(steps)
  → string  // 格式: "步骤2 [sqlmap]: SQL注入检测\n步骤3 [hydra]: 暴力破解..."
```

### 4. `executionEngine.js` 改造

当前逻辑：
```js
for (const step of steps) {
  result = await runTool(step.tool_id, args);
  // 记录结果
}
```

改造后：
```js
for (const step of steps) {
  result = await runTool(step.tool_id, args);
  // 记录结果
  
  if (engineType === 'react') {
    // 累积证据历史
    evidenceHistory.push({ stepIndex, toolId, result });
    
    // 构建 KG 上下文
    const kgContext = buildKGContextForStep(step.tool_id);
    
    // 调用 ReAct 引擎
    const decision = await reactDecide({
      runId, stepIndex, toolId, stepResult: result,
      evidenceHistory, remainingSteps, target, kgContext, aiConfig
    });
    
    // 记录 Thought/Action 到数据库
    db.prepare("UPDATE execution_steps SET react_thought=?, react_action=? ...")
      .run(decision.thought, JSON.stringify(decision.action), ...);
    
    // 处理 Action
    if (decision.action === 'stop') break;
    if (decision.action === 'adjust') { /* 修改后续步骤参数 */ }
    if (decision.action === 'insert') { /* 插入新步骤 */ }
    // 'continue' → 正常推进
  }
}
```

### 5. `llmClient.js` 增强

新增 `callLlmReact(prompt, options)` 方法：

```js
export async function callLlmReact(prompt, options = {}) {
  // 与 callLlm 相同，但：
  // 1. system prompt 固定为 ReAct 角色
  // 2. 所有错误都 resolve 为 fallback 文本（绝不 reject）
  // 3. 超时默认 30s（不是 120s）
  // 4. temperature: 0.3（更确定性）
}
```

### 6. 数据库迁移 `006_add_react_columns.js`

```sql
-- execution_runs 新增列
ALTER TABLE execution_runs ADD COLUMN engine_type TEXT DEFAULT 'mechanical';
ALTER TABLE execution_runs ADD COLUMN evidence_history TEXT;  -- JSON array
ALTER TABLE execution_runs ADD COLUMN react_thoughts TEXT;    -- JSON array of {stepIndex, thought, action}

-- execution_steps 新增列
ALTER TABLE execution_steps ADD COLUMN react_thought TEXT;    -- LLM 的分析文本
ALTER TABLE execution_steps ADD COLUMN react_action TEXT;     -- JSON: {type, attrs}
```

---

## 前端展示

### SimpleMainWindow 改造

在执行进度区域，每个步骤完成后追加一行 LLM 的 Thought：

```
[OK] 端口扫描      [██████████] 已完成
     💭 发现80端口开放，建议进行Web漏洞扫描
[OK] 漏洞扫描      [██████████] 已完成
     💭 发现XSS漏洞，攻击方案有效，继续执行
[OK] 生成攻击方案   [██████████] 已完成
>>  执行攻击       [████████░░] 执行中...
     💭 SQL注入成功，建议尝试提权...
```

实现方式：在 `updateStageRow()` 下方增加一个 `m_reactThoughtLabels[5]` 数组，每步完成后通过 `GET /api/runs/:runId` 获取 `react_thought` 并更新。

---

## 一键测试流程变化

改造后的 `onStartTest()` 流程：

```
① 端口扫描 (nmap)          → 无 LLM
② 漏洞扫描 (nuclei)        → 无 LLM  
③ 生成攻击方案             → LLM 生成 Playbook（已有）
④ 执行攻击 (ReAct 模式)    → ★ 每步执行后 LLM 分析 ★
⑤ 生成报告                 → 无 LLM（模板拼接）
```

阶段④是核心变化：不再是机械执行，而是 LLM 在每步后分析结果、决定是否调整。

---

## Fallback 策略（保证不卡死）

| 场景 | 行为 |
|------|------|
| LLM API key 未配置 | engine_type='mechanical'，走当前逻辑 |
| LLM 调用超时（30s） | 默认 Action=continue，记录超时 |
| LLM 返回无法解析 | 默认 Action=continue |
| ReAct 调用超过30次 | 后续步骤自动 continue |
| adjust 的 toolId 不存在 | 忽略 adjust，改为 continue |
| insert 的 toolId 不存在 | 忽略 insert，改为 continue |

---

## 实施顺序

1. **数据库迁移** — `006_add_react_columns.js`
2. **evidenceSerializer.js** — 纯工具函数，无依赖
3. **knowledgeEnricher.js** — 依赖 data/knowledge/ JSON
4. **llmClient.js 增强** — 新增 `callLlmReact()`
5. **reactEngine.js** — 核心引擎，依赖 2/3/4
6. **executionEngine.js 改造** — 集成 reactEngine
7. **runs.js 路由** — 新增 API 端点
8. **前端改造** — 显示 ReAct Thought

---

## 验证方案

1. **无 LLM 场景**：`engine_type='mechanical'`，行为与当前完全一致
2. **有 LLM 场景**：`engine_type='react'`，每步后数据库中 `react_thought` 非空
3. **LLM 故障场景**：断开 API key，ReAct 自动 fallback 到 continue，不卡死
4. **一键测试**：学生点击一键测试，阶段④执行时进度区显示 💭 Thought
5. **Action=stop**：LLM 判断攻击成功后提前终止，`execution_runs.stop_reason` 非空
6. **Action=adjust**：LLM 修改后续步骤参数，`execution_steps.args` 被更新
