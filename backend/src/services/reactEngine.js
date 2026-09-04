/**
 * ReAct Execution Engine
 *
 * Ported from RedTeam-Edu's playbookRuntime.js ReAct loop.
 * After each tool step (success or failure), calls LLM to analyze results
 * and decide next action. Runs on EVERY step unconditionally.
 *
 * Action types:
 *   - continue: proceed to next step as planned
 *   - adjust:   modify a future step's args (or retry current with new args)
 *   - insert:   insert a new step after current position
 *   - parallel: insert a group of parallel steps after current position
 *   - stop:     terminate the run early (with safety valve)
 *
 * Safety: never hangs — all LLM failures default to "continue".
 */

import { callLlmReact } from './llmClient.js';
import { buildKGContextForStep } from './knowledgeEnricher.js';
import { serializeEvidenceHistory, serializeCurrentPlan } from './evidenceSerializer.js';
import { buildInsertionWarning, validateInsertion } from './reactRuntimeGuard.js';
import { IMAGE_MAP } from '../tools/toolRunner.js';

const MAX_REACT_CALLS = 30;  // Safety: max LLM calls per run
const MAX_THOUGHT_LEN = 500; // Truncate LLM thought for display

// ── Clean LLM output: strip English boilerplate, keep Chinese ──────────
// Ported from old system's cleanThoughtText (playbookRuntime.js L423-501)

const BOIL_LINE_PATTERNS = [
  /^Here'?s?\s*a?\s*thinking\s*process/im,
  /^Here\s+is\s+my\s+analysis/im,
  /^Let\s+me\s+(analyze|think|check|review|consider|examine|break\s+down)/im,
  /^I\s+(need\s+to|will|should|must|can)\s+[a-z]/im,
  /^Based\s+on\s+(the\s+)?observation/im,
  /^From\s+the\s+(output|result)/im,
  /^The\s+(output|result|scan|tool)\s+(shows|indicates|reveals)/im,
  /^Looking\s+at\s+the\s+(output|result)/im,
  /^According\s+to\s+the\s+(output|scan)/im,
  /^(OK|Okay|Alright|Well|So|Now|First|Next|Then|Finally|Also|Thus|Hence|Therefore)[,，。.\s]/im,
];

function isEnglishHeavy(text) {
  const cjk = (text.match(/[一-鿿㐀-䶿]/g) || []).length;
  const ascii = (text.match(/[a-zA-Z]/g) || []).length;
  if (cjk <= 2 && ascii > 3) return true;
  if (ascii > cjk * 2 && ascii > 8) return true;
  return false;
}

function cleanContentEnglish(content) {
  if (!content) return '';
  content = content.replace(/^(and|or|but|so|then|thus|hence|therefore|also|however|moreover|furthermore)[,，。.\s]+/i, '');
  if (isEnglishHeavy(content)) return '';
  return content;
}

function cleanThoughtText(text) {
  if (!text) return 'Observation: 执行下一步\nThought: 当前步骤按计划正常推进，无异常发现。';

  // First: reliable truncation — find last <action tag
  const actionIdx = text.lastIndexOf('<action ');
  if (actionIdx > 0) {
    const thoughtStart = Math.max(0, actionIdx - 600);
    let thought = text.substring(thoughtStart, actionIdx).trim();
    if (thought.includes('<action')) {
      thought = thought.split(/<action/)[0].trim();
    }
    const action = text.substring(actionIdx);
    text = thought + '\n' + action;
  } else if (actionIdx === -1) {
    text = text.substring(0, 500);
  }

  // Second: line-by-line cleaning (strip English boilerplate, keep Chinese)
  const lines = text.split('\n');
  const kept = [];

  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (!line) continue;

    // Remove **bold** markers
    line = line.replace(/\*\*([^*]+)\*\*/g, '$1');
    // Remove numbered prefixes like "1." "2." "1、"
    line = line.replace(/^\d+[\.\)、]\s*/, '');

    // Check for Observation:/Thought: prefixes
    const obsMatch = line.match(/^Observation\s*:\s*/i);
    const thoughtMatch = line.match(/^Thought\s*:\s*/i);
    const chnObsMatch = line.match(/^(观察|发现)\s*[:：]\s*/);
    const chnThoughtMatch = line.match(/^(分析|思考)\s*[:：]\s*/);

    if (obsMatch || chnObsMatch) {
      const prefix = obsMatch ? 'Observation: ' : (chnObsMatch ? chnObsMatch[0] : 'Observation: ');
      let content = line.slice((obsMatch || chnObsMatch)[0].length).trim();
      content = cleanContentEnglish(content);
      if (content) kept.push(prefix + content);
    } else if (thoughtMatch || chnThoughtMatch) {
      const prefix = thoughtMatch ? 'Thought: ' : (chnThoughtMatch ? chnThoughtMatch[0] : 'Thought: ');
      let content = line.slice((thoughtMatch || chnThoughtMatch)[0].length).trim();
      content = cleanContentEnglish(content);
      if (content) kept.push(prefix + content);
    } else {
      // No prefix: check if English boilerplate
      const isBoilerplate = BOIL_LINE_PATTERNS.some(p => p.test(line));
      if (isBoilerplate) continue;
      if (isEnglishHeavy(line)) continue;
      // Keep Chinese lines
      kept.push(line);
    }
  }

  let result = kept.join('\n').trim();
  if (!result || result.length <= 2) {
    return 'Observation: 执行下一步\nThought: 当前步骤按计划正常推进，无异常发现。';
  }
  if (result.length > MAX_THOUGHT_LEN) {
    result = result.slice(0, MAX_THOUGHT_LEN) + '…';
  }
  return result;
}

// ── Parse Action XML from LLM response ────────────────────────────────

function parseAction(llmResponse) {
  // Extract thought (everything before <action>)
  const rawThought = llmResponse.split(/<action/)[0]?.trim() || '';

  // Clean up using the sophisticated cleaner
  let thought = cleanThoughtText(rawThought);
  if (thought.length > MAX_THOUGHT_LEN) {
    thought = '…(推理过程已省略)…\n' + thought.slice(-MAX_THOUGHT_LEN);
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
      // Support both old format (tools='[...]') and new format (toolIds='[...]')
      const toolsStr = attrs.match(/tools='([^']*)'/)?.[1]
                    || attrs.match(/tools="([^"]*)"/)?.[1];
      const toolIdsStr = attrs.match(/toolIds='([^']*)'/)?.[1]
                      || attrs.match(/toolIds="([^"]*)"/)?.[1];
      const argsListStr = attrs.match(/argsList='([^']*)'/)?.[1]
                       || attrs.match(/argsList="([^"]*)"/)?.[1];

      let toolIds = [];
      let argsList = [];

      if (toolsStr) {
        // Old format: tools='[{"toolId":"gobuster","args":[...]},...]'
        try {
          const tools = JSON.parse(toolsStr);
          if (Array.isArray(tools)) {
            for (const t of tools) {
              if (t.toolId) {
                toolIds.push(t.toolId);
                argsList.push(t.args || []);
              }
            }
          }
        } catch {}
      } else if (toolIdsStr) {
        // New format: toolIds='["tool1","tool2"]'
        try { toolIds = JSON.parse(toolIdsStr); } catch {}
        if (argsListStr) {
          try { argsList = JSON.parse(argsListStr); } catch {}
        }
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

    case 'pivot': {
      const toolId = attrs.match(/toolId="([^"]+)"/)?.[1];
      const argsStr = attrs.match(/args='([^']*)'/)?.[1] || attrs.match(/args="([^"]*)"/)?.[1];
      let args = [];
      if (argsStr) { try { args = JSON.parse(argsStr); } catch {} }
      if (!toolId || !IMAGE_MAP[toolId]) {
        console.warn(`[ReAct] pivot: invalid toolId "${toolId}", falling back to continue`);
        return { action: 'continue', thought };
      }
      return { action: 'pivot', thought, toolId, args };
    }

    case 'stop': {
      const reason = attrs.match(/reason="([^"]+)"/)?.[1] || 'LLM决定终止';
      const finalSummary = attrs.match(/finalSummary="([^"]+)"/)?.[1] || '';
      return { action: 'stop', thought, reason, finalSummary };
    }

    case 'api_error':
      // LLM API error fallback — continue execution
      return { action: 'continue', thought: 'LLM API 错误，跳过 AI 决策继续执行' };

    default:
      console.warn(`[ReAct] Unknown action type: ${actionType}, falling back to continue`);
      return { action: 'continue', thought };
  }
}

// ── Build ReAct prompt (aligned with old system) ──────────────────────

function buildReactPrompt({ stepIndex, toolId, stepName, stepResult,
                             evidenceHistory, remainingSteps, target, targetClass,
                             kgContext, reactCallCount, guardWarning, ruleMatchContext,
                             payloadContext, failedToolsHint, currentFailHint, insertHint,
                             explorationMode }) {
  // When in exploration mode, use the exploration prompt instead
  if (explorationMode) {
    return buildExplorationPrompt({ stepIndex, toolId, stepName, stepResult,
      evidenceHistory, remainingSteps, target, targetClass,
      kgContext, reactCallCount, guardWarning, ruleMatchContext,
      payloadContext, failedToolsHint, currentFailHint, insertHint });
  }

  const success = stepResult.success ? '成功' : '失败';
  const output = (stepResult.stdout || stepResult.stderr || '').slice(0, 500);

  const evidenceText = serializeEvidenceHistory(evidenceHistory);
  const planText = serializeCurrentPlan(remainingSteps);

  return `你是 ISST 的安全测试执行代理。当前运行在 Auto-pilot 模式下。

⚠️ 重要：每次输出必须严格包含 Observation、Thought、Action 三段，不可省略任何一段。Thought 控制在 150 字以内。使用中文输出，避免英文推理过程。

【核心原则】
1. Playbook 锚定：严格推进当前 Playbook 的执行队列。可基于证据做出决策，但不能跳脱主线自行编造攻击步骤。
2. 工具沙箱【绝对红线】：禁止在你的决策中拼接 &&, ||, |, >, ;, \` 等 Shell 拼接符，禁止在自主推荐或插入步骤时调用 cat, echo, ping, bash 等系统命令。Playbook 预置步骤中已授权的命令与工具属于授信范围，必须正常推进执行，严禁拦截或终止。
3. 证据驱动：必须依赖工具的真实输出。禁止利用 LLM 先验知识盲猜（如 DVWA 默认密码）。所有漏洞验证必须走标准扫描流程。
4. 失败处理【关键】：如果当前步骤失败，你必须：(a) 用 adjust 修改参数重试；(b) 用 continue 跳过（如果该步骤结果非关键）；(c) 用 stop 终止（如果所有剩余步骤工具都在黑名单中）。

【5 种 Action — 根据证据选择最合适的】
  continue — 步骤成功完成且有有效发现，按计划继续执行下一步
  adjust   — 修改后续步骤参数，或用新参数重试当前失败步骤
  insert   — 证据显示计划有空白，插入新工具步骤（禁止插入已列入黑名单的工具）
  parallel — 多个独立扫描任务可并行执行以提高效率
  stop     — 所有计划步骤执行完毕，或目标不可达，或所有剩余步骤工具都失败。必须提供 reason。

【强制决策规则 — 当以下条件满足时你必须选择对应 Action，禁止使用 continue】
  - 当前步骤工具执行失败或输出为空 → 必须使用 adjust（修改参数重试）或 continue（跳过非关键步骤）
  - 连续 3 个及以上同类工具步骤均无有效发现 → 必须使用 adjust 更换参数/目标，或 stop 终止无效循环
  - 工具输出包含连接错误（如 DNS 解析失败、unable to connect、connection refused） → 必须使用 adjust 修正目标地址
  - 剩余步骤全部是已执行过且无发现的同类重复步骤 → 必须使用 stop 终止

${kgContext ? `## KG 知识上下文\n${kgContext}\n` : ''}${payloadContext ? `## 载荷攻防知识\n${payloadContext}\n` : ''}
证据历史：
${evidenceText}

计划：
${planText}${insertHint || ''}${failedToolsHint || ''}${currentFailHint || ''}${guardWarning || ''}${ruleMatchContext ? `\n## 规则引擎匹配\n${ruleMatchContext}` : ''}

输出格式：
Observation: <用中文一句话总结最新步骤的执行结果与关键证据发现，不可省略>
Thought: <用中文分析当前计划是否仍有效、下一步应该做什么，不可省略>
Action: 使用以下 XML 格式之一：
  <action type="continue" toolId="xxx" args='["arg1", "arg2"]' />
  <action type="adjust" toolId="xxx" newArgs='["new1", "new2"]' stepIndex="当前步骤索引" />
  <action type="insert" toolId="xxx" args='["arg1", "arg2"]' position="after" />
  <action type="parallel" tools='[{"toolId":"gobuster","args":["-m","dir","-u","http://target:8080","-w","config/wordlists/common_dirs.txt"]}]' />
  <action type="stop" reason="总结原因" finalSummary="最终报告文本" />

注意：args 必须为严格的 JSON 序列化数组。不要输出任何其他内容。`;
}

// ── Build exploration-mode prompt ──────────────────────────────────────

function buildExplorationPrompt({ stepIndex, toolId, stepName, stepResult,
                                    evidenceHistory, remainingSteps, target, targetClass,
                                    kgContext, reactCallCount, guardWarning, ruleMatchContext,
                                    payloadContext, failedToolsHint, currentFailHint, insertHint }) {
  const success = stepResult.success ? '成功' : '失败';
  const output = (stepResult.stdout || stepResult.stderr || '').slice(0, 500);

  const evidenceText = serializeEvidenceHistory(evidenceHistory);
  const planText = serializeCurrentPlan(remainingSteps);

  return `你是 ISST 的安全测试执行代理。当前运行在 Exploration 模式下，目标是探索未知的攻击面。

【核心原则 — 探索模式】
1. 证据优先：所有决策必须基于工具的真实输出结果。禁止依赖 LLM 先验知识推测目标特性（如默认密码、常见路径、框架版本）。
2. 鼓励探索：当发现新的攻击面（新端口、服务、路径、参数）时，必须优先使用 insert 插入新的探测步骤，而不是继续执行原计划。探索范围越大越好。
3. 快速失败：如果同一攻击路径连续失败 2 次，必须立即切换方向。禁止反复重试同一工具/参数组合。
4. 广度优先：先尽可能枚举所有攻击面（端口、目录、子域名、参数），再对已确认存在的攻击面进行深度利用。不要过早陷入单一攻击路径的深度挖掘。
5. 禁止盲猜：绝对禁止利用 LLM 先验知识推断目标存在某特性。所有发现必须源自工具的真实输出。例如：未扫描到 80 端口就绝不能说目标有 HTTP 服务；未扫描到某个路径就不能假定目标有该端点。

【5 种 Action — 选择规则】
  continue — 当前步骤无有效发现，按计划继续下一步。只有当没有新的攻击面需要探索时才使用。
  adjust   — 修改参数后重试当前失败步骤。如果同一工具连续 2 次失败，改用 pivot 切换方向。
  insert   — 发现新攻击面时插入新的探测步骤。探索模式下 insert 的优先级高于 continue。禁止插入已列入黑名单的工具。
  pivot    — 当前攻击路径连续失败或已充分探索，切换到全新的攻击方向。使用 toolId 和 args 指定新工具和参数。
  parallel — 多个独立的探测任务可以并行执行以提高效率。
  stop     — 所有攻击面已探索完毕，或目标不可达，或所有可用工具都已耗尽。必须提供 reason。

【强制决策规则 — 探索模式】
  - 发现 HTTP 服务端口 → 必须 insert gobuster/ffuf 进行目录枚举
  - 发现 API 路径 → 必须 insert arjun 进行参数发现
  - 发现登录表单 → 必须 insert hydra 进行认证测试
  - 发现 SQL 错误 → 必须 insert sqlmap 进行 SQL 注入测试
  - 发现 Actuator/敏感端点 → 必须 insert curl 进行信息泄露检测
  - 发现 JWT Token → 必须 insert jwt_tool 进行 JWT 攻击测试
  - 连续 2 次失败 → 必须使用 pivot 切换攻击方向，禁止反复重试
  - 未发现任何攻击面 → 使用 continue 推进至下一步探测

${kgContext ? `## KG 知识上下文\n${kgContext}\n` : ''}${payloadContext ? `## 载荷攻防知识\n${payloadContext}\n` : ''}
证据历史：
${evidenceText}

计划：
${planText}${insertHint || ''}${failedToolsHint || ''}${currentFailHint || ''}${guardWarning || ''}${ruleMatchContext ? `\n## 规则引擎匹配\n${ruleMatchContext}` : ''}

输出格式：
Observation: <用中文一句话总结最新步骤的执行结果与关键证据发现，不可省略>
Thought: <用中文分析当前已发现的攻击面、下一步探索方向，不可省略>
Action: 使用以下 XML 格式之一：
  <action type="continue" toolId="xxx" args='["arg1", "arg2"]' />
  <action type="adjust" toolId="xxx" newArgs='["new1", "new2"]' stepIndex="当前步骤索引" />
  <action type="insert" toolId="xxx" args='["arg1", "arg2"]' position="after" />
  <action type="pivot" toolId="xxx" args='["arg1", "arg2"]' />
  <action type="parallel" tools='[{"toolId":"gobuster","args":["-m","dir","-u","http://target:8080","-w","config/wordlists/common_dirs.txt"]}]' />
  <action type="stop" reason="总结原因" finalSummary="最终报告文本" />

注意：args 必须为严格的 JSON 序列化数组。不要输出任何其他内容。`;
}

// ── Build all insert hints (rule-based) ───────────────────────────────

function buildAllInsertHints({ evidenceHistory, stepResult, remainingSteps, target, guardState }) {
  const hints = [];
  const allEvidence = evidenceHistory.map(e => JSON.stringify(e)).join(' ');
  const currentOutput = (stepResult.stdout || '');

  // Helper to check if a tool is already in the plan
  function toolInPlan(toolId) {
    const planToolIds = (remainingSteps || []).map(s => s.tool_id || s.toolId);
    const guardToolIds = (guardState?.steps || []).map(s => s.tool_id || s.toolId);
    return planToolIds.includes(toolId) || guardToolIds.includes(toolId);
  }

  // Build target URL helper
  function buildTargetUrl(scheme = 'http') {
    let url = target || '';
    try {
      if (target && !target.startsWith('http')) {
        url = `${scheme}://${target}`;
      }
    } catch {}
    return url;
  }

  // Rule 1: HTTP port detected → directory enumeration
  {
    const hasHttpPort = /\b(80|8080|8000|8443|3000|3001|5000|5001|5901)\b.*open|open.*\b(80|8080|8000|8443|3000|3001|5000|5001|5901)\b/i.test(allEvidence)
      || currentOutput.match(/\b(80|8080|8000|8443|3000|3001|5000|5001|5901)\/tcp.*open/i);

    if (hasHttpPort && !toolInPlan('gobuster') && !toolInPlan('dirb') && !toolInPlan('ffuf')) {
      const targetUrl = buildTargetUrl();
      hints.push(`\n\n⚠️ 强制规则 [规则1]：证据显示目标存在 HTTP 服务端口，但当前计划中没有目录枚举步骤。你必须使用 insert Action 插入 gobuster 目录枚举步骤，例如：\n<action type="insert" toolId="gobuster" args='["-m", "dir", "-u", "${targetUrl}", "-w", "config/wordlists/common_dirs.txt"]' position="after" />\n这是强制要求，不允许使用 continue。`);
    }
  }

  // Rule 2: API path detected → parameter discovery (arjun)
  {
    const hasApiPath = /\/api\/|\/v\d+\/|\/graphql|\/swagger|\/openapi/i.test(allEvidence)
      || /\/api\/|\/v\d+\/|\/graphql|\/swagger|\/openapi/i.test(currentOutput);

    if (hasApiPath && !toolInPlan('arjun')) {
      const targetUrl = buildTargetUrl();
      hints.push(`\n\n📌 建议规则 [规则2]：检测到 API 路径，建议使用 arjun 进行参数发现：\n<action type="insert" toolId="arjun" args='["-u", "${targetUrl}", "--passive"]' position="after" />`);
    }
  }

  // Rule 3: Login form detected → auth testing (hydra)
  {
    const hasLoginForm = /\b(login|signin|auth|admin|user|password|passwd)\b/i.test(allEvidence)
      || /\b(login|signin|auth)\b/i.test(currentOutput);

    if (hasLoginForm && !toolInPlan('hydra')) {
      const targetUrl = buildTargetUrl();
      hints.push(`\n\n📌 建议规则 [规则3]：检测到登录表单，建议使用 hydra 进行认证测试：\n<action type="insert" toolId="hydra" args='["-l", "admin", "-P", "config/wordlists/common_passwords.txt", "${targetUrl}", "http-post-form", "/login:user=^USER^&pass=^PASS^:F=incorrect"]' position="after" />`);
    }
  }

  // Rule 4: SQL error detected → SQL injection testing (sqlmap)
  {
    const hasSqlError = /\b(SQL|syntax error|mysql_fetch|ORA-[0-9]|SQLite|Unclosed quotation mark)\b/i.test(allEvidence)
      || /\b(SQL|syntax error|mysql_fetch|ORA-[0-9])\b/i.test(currentOutput);

    if (hasSqlError && !toolInPlan('sqlmap')) {
      const targetUrl = buildTargetUrl();
      hints.push(`\n\n🚨 强制规则 [规则4]：检测到 SQL 错误信息，存在 SQL 注入风险。你必须使用 insert Action 插入 sqlmap 进行注入测试：\n<action type="insert" toolId="sqlmap" args='["-u", "${targetUrl}", "--batch", "--random-agent"]' position="after" />\n这是强制要求，不允许使用 continue。`);
    }
  }

  // Rule 5: Actuator endpoint → info leak testing (curl)
  {
    const hasActuator = /\b(actuator|heapdump|threaddump|env|metrics|health|info|beans|mappings)\b/i.test(allEvidence)
      || /\b(actuator|heapdump|threaddump)\b/i.test(currentOutput);

    if (hasActuator && !toolInPlan('curl') && !toolInPlan('wget')) {
      hints.push(`\n\n📌 建议规则 [规则5]：检测到 Actuator/敏感端点，建议使用 curl 进行信息泄露检测。`);
    }
  }

  // Rule 6: JWT token detected → JWT attack testing
  {
    const hasJwt = /\b(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+|jwt|JWT|Bearer)\b/i.test(allEvidence)
      || /\b(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+|jwt|JWT|Bearer)\b/i.test(currentOutput);

    if (hasJwt && !toolInPlan('jwt_tool') && !toolInPlan('jwt-cracker')) {
      hints.push(`\n\n📌 建议规则 [规则6]：检测到 JWT Token，建议使用 jwt_tool 进行 JWT 攻击测试。`);
    }
  }

  return hints.join('\n\n');
}

// ── Main entry: ReAct decision after each step ────────────────────────

/**
 * Called after each tool execution step to get LLM's analysis and decision.
 * Runs on EVERY step (including failed ones and the last step).
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
 * @param {string} [params.payloadContext] - payload attack-defense knowledge
 * @param {Array}  [params.failedToolCounts] - [{ toolId, count }] for blacklist
 * @param {number} params.totalSteps - total steps in current plan
 * @param {number} params.completedSteps - steps completed so far
 * @returns {Promise<{action, thought, observation?, toolId?, newArgs?, args?, reason?, toolIds?, argsList?}>}
 */
export async function reactDecide(params) {
  const {
    runId, stepIndex, toolId, stepName, stepResult,
    evidenceHistory, remainingSteps, target, targetClass,
    aiConfig, reactCallCount = 0, guardState, ruleMatchContext,
    payloadContext, failedToolCounts = [], totalSteps = 0, completedSteps = 0,
    explorationMode = false,
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

  // ── Failed tool blacklist (from old system Issue #3 fix) ────────────
  const failedToolsList = failedToolCounts
    .filter(f => f.count >= 3)
    .map(f => f.toolId);
  const failedToolsHint = failedToolsList.length > 0
    ? `\n\n🚫 【失败工具黑名单 - 绝对禁止】以下工具在本次运行中已失败3次以上，你绝对不允许再次 insert 这些工具，否则会导致无限循环：[${failedToolsList.join(', ')}]。如果下一步计划使用这些工具，必须使用 continue 跳过或 stop 终止。`
    : '';

  // ── Current step failure hint ────────────────────────────────────────
  const currentStepFailed = !stepResult.success;
  const currentFailHint = currentStepFailed
    ? `\n\n⛔ 【当前步骤失败警告】工具 ${toolId} 执行失败（exit_code=${stepResult.exitCode}）。你可以：(1) 使用 adjust 修改参数后重试；(2) 使用 continue 跳过当前步骤继续执行下一步；(3) 如果后续步骤依赖此工具且无法替代，使用 stop 终止。禁止使用 insert 再次插入工具 ${toolId}。`
    : '';

  // ── Insert hints (rule-based) ────────────────────────────────────────
  const insertHint = buildAllInsertHints({
    evidenceHistory, stepResult, remainingSteps, target, guardState,
  });

  // Build prompt
  const prompt = buildReactPrompt({
    stepIndex, toolId, stepName, stepResult,
    evidenceHistory, remainingSteps, target, targetClass,
    kgContext, reactCallCount, guardWarning, ruleMatchContext,
    payloadContext, failedToolsHint, currentFailHint, insertHint,
    explorationMode,
  });

  // Call LLM (never throws — returns fallback on failure)
  console.log(`[ReAct] Step ${stepIndex} [${toolId}]: calling LLM (call #${reactCallCount + 1})`);
  const rawResponse = await callLlmReact(prompt, aiConfig || {});

  // Clean and parse response
  const decision = parseAction(rawResponse);

  // ── Stop safety valve (from old system) ──────────────────────────────
  // Prevent premature stop when >70% steps remain (unless all remaining tools blacklisted)
  if (decision.action === 'stop') {
    const remainingCount = totalSteps - completedSteps - 1; // exclude current
    const remainingRatio = totalSteps > 0 ? remainingCount / totalSteps : 0;

    const remainingStepTools = (remainingSteps || []).map(s => s.tool_id || s.toolId);
    const allRemainingBlacklisted = remainingStepTools.length > 0 &&
      remainingStepTools.every(t => failedToolsList.includes(t));

    if (remainingRatio > 0.7 && totalSteps > 2 && !allRemainingBlacklisted) {
      console.log(`[ReAct] 🛑 stop 被安全阀拦截: 剩余步骤比例=${remainingRatio.toFixed(2)} (${remainingCount}/${totalSteps}), 强制转为 continue`);
      return { action: 'continue', thought: `stop 被安全阀拦截（剩余 ${remainingCount}/${totalSteps} 步骤），强制继续` };
    }

    if (allRemainingBlacklisted) {
      console.log(`[ReAct] 🛑 stop 安全阀黑名单豁免: 剩余 ${remainingCount} 个步骤的工具全部在黑名单中 [${remainingStepTools.join(', ')}]，允许 stop`);
    }
  }

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
