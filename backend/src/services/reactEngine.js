/**
 * ReAct Execution Engine
 *
 * Implements the Reasoning + Acting loop from RedTeam-Edu's playbookRuntime.js.
 * After each tool step, calls LLM to analyze results and decide next action.
 *
 * Action types:
 *   - continue: proceed to next step as planned
 *   - adjust:   modify a future step's args
 *   - insert:   insert a new step after current position
 *   - parallel: insert a group of parallel steps after current%  current position
 *   - stop:     terminate the run early
 *
 * Safety: never hangs — all LLM failures default to "continue".
 */

import { callLlmReact } from './llmClient.js';
import { buildKGContextForStep } from './knowledgeEnricher.js';
import { serializeEvidenceHistory, serializeCurrentPlan } from './evidenceSerializer.js';
import { buildInsertionWarning } from './reactRuntimeGuard.js';
import { IMAGE_MAP } from '../tools/toolRunner.js';

const MAX_REACT_CALLS = 30;  // Safety: max LLM calls per run
const MAX_THOUGHT_LEN = 500; // Truncate LLM thought for display

// ── Clean LLM output: extract Observation/Thought/Action ──────────────

function cleanThoughtText(text) {
  if (!text) return 'Observation: 执行下一步\nThought: 按计划正常推进。';

  // Find the last <action tag
  const actionIdx = text.lastIndexOf('<action ');
  if (actionIdx > 0) {
    // Take up to 600 chars before <action as Observation/Thought
    const thoughtStart = Math.max(0, actionIdx - 600);
    let thought = text.substring(thoughtStart, actionIdx).trim();
    // If thought still contains <action (nested), strip it
    if (thought.includes('<action')) {
      thought = thought.split(/<action/)[0].trim();
    }
    const action = text.substring(actionIdx);
    return thought + '\n' + action;
  }

  // No <action tag found — return truncated text
  return text.substring(0, 500);
}

// ── Parse Action XML from LLM response ────────────────────────────────

function parseAction(llmResponse) {
  // Extract thought (everything before <action)
  const rawThought = llmResponse.split(/<action/)[0]?.trim() || '';

  // Clean up: keep only Observation/Thought lines
  const thoughtLines = [];
  for (const line of rawThought.split('\n')) {
    const trimmed = line.trim();
    if (/^(Observation|Thought|分析|思考)\s*[:：]/i.test(trimmed)) {
      thoughtLines.push(trimmed);
    } else if (/[一-鿿]/.test(trimmed) && trimmed.length < 200) {
      // Keep Chinese lines (likely useful analysis)
      thoughtLines.push(trimmed);
    }
  }
  let thought = thoughtLines.join('\n');
  if (thought.length > MAX_THOUGHT_LEN) {
    thought = thought.slice(0, MAX_THOUGHT_LEN) + '…';
  }
  if (!thought) {
    thought = '按计划正常推进';
  }

  // Parse <action type="..." ... />
  const actionMatch = llmResponse.match(/<action\s+type="([^"]+)"([^>]*?)\s*\/?>/);
  if (!actionMatch) {
    return { action: 'continue', thought, observation: '' };
  }

  const actionType = actionMatch[1];
  const attrs = actionMatch[2];

  switch (actionType) {
    case 'continue':
      return { action: 'continue', thought };

    case 'adjust': {
      const toolId = attrs.match(/toolId="([^"]+)"/)?.[1];
      const newArgsStr = attrs.match(/newArgs='([^']*)'/)?.[1]
                      || attrs.match(/newArgs="([^"]*)"/)?.[1];
      const stepIndex = parseInt(attrs.match(/stepIndex="(\d+)"/)?.[1], 10);
      let newArgs = null;
      if (newArgsStr) {
        try { newArgs = JSON.parse(newArgsStr); } catch {}
      }
      if (!toolId || !IMAGE_MAP[toolId]) {
        console.warn(`[ReAct] adjust: invalid toolId "${toolId}", falling back to continue`);
        return { action: 'continue', thought };
      }
      return { action: 'adjust', thought, toolId, newArgs, stepIndex };
    }

    case 'insert': {
      const toolId = attrs.match(/toolId="([^"]+)"/)?.[1];
      const argsStr = attrs.match(/args='([^']*)'/)?.[1]
                   || attrs.match(/args="([^"]*)"/)?.[1];
      let args = [];
      if (argsStr) {
        try { args = JSON.parse(argsStr); } catch {}
      }
      if (!toolId || !IMAGE_MAP[toolId]) {
        console.warn(`[ReAct] insert: invalid toolId "${toolId}", falling back to continue`);
        return { action: 'continue', thought };
      }
      return { action: 'insert', thought, toolId, args, position: 'after' };
    }

    case 'parallel': {
      const toolIdsStr = attrs.match(/toolIds='([^']*)'/)?.[1]
                      || attrs.match(/toolIds="([^"]*)"/)?.[1];
      const argsListStr = attrs.match(/argsList='([^']*)'/)?.[1]
                       || attrs.match(/argsList="([^"]*)"/)?.[1];
      let toolIds = [];
      let argsList = [];
      if (toolIdsStr) {
        try { toolIds = JSON.parse(toolIdsStr); } catch {}
      }
      if (argsListStr) {
        try { argsList = JSON.parse(argsListStr); } catch {}
      }
      // Validate all toolIds exist in IMAGE_MAP
      const validToolIds = toolIds.filter(tid => IMAGE_MAP[tid]);
      if (validToolIds.length === 0) {
        console.warn(`[ReAct] parallel: no valid toolIds in ${JSON.stringify(toolIds)}, falling back to continue`);
        return { action: 'continue', thought };
      }
      if (validToolIds.length < toolIds.length) {
        console.warn(`[ReAct] parallel: some toolIds invalid, keeping ${validToolIds.length}/${toolIds.length}`);
      }
      // Pad argsList if shorter than toolIds
      while (argsList.length < validToolIds.length) argsList.push([]);
      return { action: 'parallel', thought, toolIds: validToolIds, argsList };
    }

    case 'stop': {
      const reason = attrs.match(/reason="([^"]+)"/)?.[1] || 'LLM决定终止';
      return { action: 'stop', thought, reason };
    }

    default:
      console.warn(`[ReAct] Unknown action type: ${actionType}, falling back to continue`);
      return { action: 'continue', thought };
  }
}

// ── Build ReAct prompt ────────────────────────────────────────────────

function buildReactPrompt({ stepIndex, toolId, stepName, stepResult,
                             evidenceHistory, remainingSteps, target, targetClass,
                             kgContext, reactCallCount, guardWarning, ruleMatchContext }) {
  const success = stepResult.success ? '成功' : '失败';
  const output = (stepResult.stdout || stepResult.stderr || '').slice(0, 500);

  const evidenceText = serializeEvidenceHistory(evidenceHistory);
  const planText = serializeCurrentPlan(remainingSteps);

  return `你是渗透测试执行代理，当前运行在 Auto-pilot 模式。

## 当前执行状态
- 目标: ${target}${targetClass ? `\n- 靶场类型: ${targetClass}` : ''}
- 已完成: ${evidenceHistory.length} 步
- 当前步骤: step${stepIndex} [${toolId}] ${stepName || ''} — ${success}
- 最新输出: ${output.slice(0, 300)}

## 执行证据历史
${evidenceText}

## 剩余计划
${planText}

${kgContext ? `## KG 知识上下文\n${kgContext}\n` : ''}${ruleMatchContext ? `## 规则引擎匹配\n${ruleMatchContext}\n` : ''}${guardWarning || ''}输出格式：
Observation: <用中文一句话总结最新步骤的执行结果与关键证据发现，不可省略>
Thought: <用中文分析当前计划是否仍有效、下一步应该做什么，不可省略>
Action: 使用以下 XML 格式之一：
  <action type="continue" />
  <action type="adjust" toolId="xxx" newArgs='["arg1", "arg2"]' stepIndex="步骤索引" />
  <action type="insert" toolId="xxx" args='["arg1", "arg2"]' position="after" />
  <action type="parallel" toolIds='["tool1","tool2"]' argsList='[["arg1"],["arg1","arg2"]]' />
  <action type="stop" reason="终止原因" />

注意：args/argsList 必须为严格的 JSON 序列化数组。parallel 用于同时插入多个工具步骤。不要输出任何其他内容。`;
}

// ── Main entry: ReAct decision after each step ────────────────────────

/**
 * Called after each tool execution step to get LLM's analysis and decision.
 *
 * @param {object} params
 * @param {string} params.runId
 * @param {number} params.stepIndex
 * @param {string} params.toolId
 * @param {string} params.stepName
 * @param {object} params.stepResult - { success, stdout, stderr, exitCode }
 * @param {Array}  params.evidenceHistory - accumulated evidence
 * @param {Array}  params.remainingSteps - remaining playbook steps
 * @param {string} params.target
 * @param {object} [params.aiConfig] - optional AI config override
 * @param {number} params.reactCallCount - how many times ReAct has been called
 * @param {object} [params.guardState] - { steps, status, stopReason } for Guard warning
 * @param {string} [params.ruleMatchContext] - rule match summary for prompt injection
 * @returns {Promise<{action, thought, observation?, toolId?, newArgs?, args?, reason?, toolIds?, argsList?}>}
 */
export async function reactDecide(params) {
  const {
    runId, stepIndex, toolId, stepName, stepResult,
    evidenceHistory, remainingSteps, target, targetClass,
    aiConfig, reactCallCount = 0, guardState, ruleMatchContext,
  } = params;

  // Safety: if ReAct called too many times, auto-continue
  if (reactCallCount >= MAX_REACT_CALLS) {
    console.log(`[ReAct] Call limit reached (${reactCallCount}/${MAX_REACT_CALLS}), auto-continue`);
    return { action: 'continue', thought: 'ReAct调用次数已达上限，自动继续' };
  }

  // Build KG context for this tool
  const kgContext = buildKGContextForStep(toolId);

  // Build Guard warning for insertion limits
  let guardWarning = '';
  if (guardState) {
    guardWarning = buildInsertionWarning(guardState);
  }

  // Build prompt
  const prompt = buildReactPrompt({
    stepIndex, toolId, stepName, stepResult,
    evidenceHistory, remainingSteps, target, targetClass,
    kgContext, reactCallCount, guardWarning, ruleMatchContext,
  });

  // Call LLM (never throws — returns fallback on failure)
  console.log(`[ReAct] Step ${stepIndex} [${toolId}]: calling LLM (call #${reactCallCount + 1})`);
  const rawResponse = await callLlmReact(prompt, aiConfig || {});

  // Clean and parse response
  const cleaned = cleanThoughtText(rawResponse);
  const decision = parseAction(cleaned);

  console.log(`[ReAct] Step ${stepIndex}: action=${decision.action}, thought="${decision.thought?.slice(0, 80)}"`);

  return decision;
}

/**
 * Check if ReAct engine should be used for a given run.
 * Reads engine_type from execution_runs table.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} runId
 * @returns {boolean}
 */
export function isReactEngine(db, runId) {
  const run = db.prepare('SELECT engine_type FROM execution_runs WHERE run_id = ?').get(runId);
  return run?.engine_type === 'react';
}

/**
 * Determine engine type based on LLM availability.
 * If LLM API key is configured → 'react', else 'mechanical'.
 *
 * @param {import('better-sqlite3').Database} db
 * @returns {'react' | 'mechanical'}
 */
export function determineEngineType(db) {
  const rows = db.prepare(
    "SELECT config_value FROM system_config WHERE category = 'llm'"
  ).all();

  for (const row of rows) {
    try {
      const cfg = JSON.parse(row.config_value);
      if (cfg.key && cfg.key.length > 0) return 'react';
    } catch {}
  }

  // Check env vars
  if (process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || process.env.DEEPSEEK_API_KEY) {
    return 'react';
  }

  return 'mechanical';
}
