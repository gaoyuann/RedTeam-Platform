import { getDb } from '../db/connection.js';
import { callLlm } from './llmClient.js';
import { resolveTargetProfile } from './targetProfileResolver.js';

// ── Constants ──────────────────────────────────────────────────────────────

const MAX_FINDINGS_ENTRIES = 30;   // max scan result entries to include in prompt
const MAX_DATA_STR_LEN = 300;      // per-entry truncation
const MAX_FINDINGS_TEXT_LEN = 10000; // total findings text cap

// ── Helper: build a concise findings summary from scan results ─────────────

function buildFindingsSummary(scanResults) {
  const lines = [];

  for (const r of scanResults) {
    if (r.result_type === 'raw_output') continue; // skip raw tool noise

    let dataStr = '';
    try {
      const d = JSON.parse(r.result_data || '{}');
      dataStr = Object.entries(d)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ');
    } catch {
      dataStr = (r.result_data || '').slice(0, MAX_DATA_STR_LEN);
    }
    if (dataStr.length > MAX_DATA_STR_LEN) {
      dataStr = dataStr.slice(0, MAX_DATA_STR_LEN) + '...';
    }

    lines.push(
      `- [${r.severity || 'info'}] ${r.result_type}: ${dataStr} (tool: ${r.source_tool || '?'}, mitre: ${r.mitre_technique_id || 'N/A'})`
    );
  }

  let text = lines.length > 0 ? lines.join('\n') : '（无具体发现）';

  if (text.length > MAX_FINDINGS_TEXT_LEN) {
    text = text.slice(0, MAX_FINDINGS_TEXT_LEN) + '\n...(更多发现已截断)';
  }

  return text;
}

// ── Helper: aggregate results from one or more scan tasks ──────────────────

function getScanResults(db, scanTaskIds) {
  const ids = Array.isArray(scanTaskIds) ? scanTaskIds : (scanTaskIds ? scanTaskIds.split(',') : []);

  if (ids.length === 0) return [];

  const placeholders = ids.map(() => '?').join(',');
  return db.prepare(
    `SELECT result_type, result_data, severity, mitre_technique_id, source_tool
     FROM scan_results WHERE scan_task_id IN (${placeholders})
     ORDER BY CASE severity
       WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
       WHEN 'low' THEN 3 ELSE 4 END
     LIMIT ?`
  ).all(...ids, MAX_FINDINGS_ENTRIES);
}

// ── Helper: validate and normalize LLM JSON output ─────────────────────────

function validateAnalysisJson(parsed) {
  const result = {
    tech_stack: null,
    attack_surface: null,
    risk_assessment: null,
    recommended_strategy: null,
  };

  if (parsed.tech_stack || parsed.techStack || parsed.技术栈) {
    result.tech_stack = parsed.tech_stack || parsed.techStack || parsed.技术栈;
  }
  if (parsed.attack_surface || parsed.attackSurface || parsed.攻击面) {
    result.attack_surface = parsed.attack_surface || parsed.attackSurface || parsed.攻击面;
  }
  if (parsed.risk_assessment || parsed.riskAssessment || parsed.风险评估) {
    result.risk_assessment = parsed.risk_assessment || parsed.riskAssessment || parsed.风险评估;
  }
  if (parsed.recommended_strategy || parsed.recommendedStrategy || parsed.推荐策略 || parsed.recommended_attack_strategy || parsed.推荐攻击策略) {
    result.recommended_strategy = parsed.recommended_strategy || parsed.recommendedStrategy || parsed.推荐策略 || parsed.recommended_attack_strategy || parsed.推荐攻击策略;
  }

  // Use raw field names if they already match our schema
  if (parsed.tech_stack !== undefined) result.tech_stack = parsed.tech_stack;
  if (parsed.attack_surface !== undefined) result.attack_surface = parsed.attack_surface;
  if (parsed.risk_assessment !== undefined) result.risk_assessment = parsed.risk_assessment;
  if (parsed.recommended_strategy !== undefined) result.recommended_strategy = parsed.recommended_strategy;

  return result;
}

// ── Main entry: analyze scan results using LLM ─────────────────────────────

/**
 * Analyze scan results using LLM and return a structured analysis.
 *
 * @param {string|string[]} scanTaskId - Single scan task ID or array of IDs
 * @param {object} [options]
 * @param {string} [options.target] - Override target (otherwise read from scan_tasks)
 * @returns {Promise<{ok: boolean, data?: object, error?: string}>}
 */
export async function analyzeScanResults(scanTaskIds, options = {}) {
  const db = getDb();

  // Normalize IDs
  const ids = Array.isArray(scanTaskIds) ? scanTaskIds : (scanTaskIds ? [scanTaskIds] : []);
  if (ids.length === 0) {
    return { ok: false, error: 'No scan task IDs provided' };
  }

  // Get scan tasks
  const placeholders = ids.map(() => '?').join(',');
  const tasks = db.prepare(
    `SELECT scan_task_id, target, scan_type, target_class FROM scan_tasks
     WHERE scan_task_id IN (${placeholders})`
  ).all(...ids);

  if (tasks.length === 0) {
    return { ok: false, error: 'No scan tasks found for given IDs' };
  }

  // Determine target: use override, or first task's target
  const target = options.target || tasks[0].target;

  // Resolve target profile for context
  const targetProfile = resolveTargetProfile(target);

  // Gather all scan results
  const results = getScanResults(db, ids);
  const findingsSummary = buildFindingsSummary(results);

  // Determine which scan types were run
  const scanTypesRun = [...new Set(tasks.map(t => t.scan_type))];
  const targetClass = tasks[0].target_class || targetProfile.target_class;

  // ── LLM Prompt (Chinese) ─────────────────────────────────────────────

  const prompt = `你是一名资深的红队渗透测试分析师。请根据以下扫描结果，对目标进行全面的分析评估，并输出**严格的结构化 JSON**。

## 目标信息
- 目标地址：${target}
- 目标类型：${targetClass}
- 已执行扫描：${scanTypesRun.join(', ')}

## 扫描发现摘要
${findingsSummary}

## 输出要求

请输出一个 JSON 对象（不要 markdown 包裹，不要额外说明），包含以下四个字段：

1. **tech_stack**（技术栈识别）：数组，列出目标可能使用的技术组件。每一项包含：
   - \`category\`：分类（语言/框架/中间件/数据库/操作系统）
   - \`name\`：名称
   - \`confidence\`：置信度（high/medium/low）
   - \`evidence\`：依据（来自哪条扫描发现）

2. **attack_surface**（攻击面清单）：数组，列出可攻击的面。每一项包含：
   - \`type\`：类型（端口/路径/API/认证方式/服务）
   - \`detail\`：具体描述
   - \`severity\`：严重程度
   - \`accessible\`：是否可直接访问

3. **risk_assessment**（风险评估）：数组，按 OWASP Top 10 或 MITRE ATT&CK 分类的风险项。每一项包含：
   - \`category\`：风险类别（如 "A1: 注入"、"T1078: 有效账号"）
   - \`description\`：描述
   - \`level\`：风险等级（critical/high/medium/low）
   - \`affected_components\`：受影响组件

4. **recommended_strategy**（推荐攻击策略）：数组，按优先级排序的攻击建议。每一项包含：
   - \`priority\`：优先级（1 最高）
   - \`strategy\`：策略名称
   - \`description\`：详细说明
   - \`suggested_tools\`：建议使用的工具列表
   - \`expected_gain\`：预期收益`;

  const messages = [
    {
      role: 'system',
      content: '你是一名专业的渗透测试分析专家。请严格按照要求的 JSON 格式输出分析结果，不要添加任何额外的文字说明。',
    },
    { role: 'user', content: prompt },
  ];

  const llmResult = await callLlm(messages, { temperature: 0.3, maxTokens: 4096 });

  if (!llmResult.ok) {
    return { ok: false, error: `LLM 分析失败: ${llmResult.error}` };
  }

  // ── Parse LLM response ───────────────────────────────────────────────

  let parsed;
  try {
    const content = llmResult.content.trim();
    // Strip markdown code fences if present
    const jsonStr = content.replace(/^```(?:json)?\n?/i, '').replace(/\n?```\s*$/, '').trim();
    parsed = JSON.parse(jsonStr);
  } catch (err) {
    return {
      ok: false,
      error: `LLM 返回不是有效的 JSON: ${err.message}`,
      raw: llmResult.content.slice(0, 1000),
    };
  }

  // Validate and normalize
  const validated = validateAnalysisJson(parsed);

  // Ensure all four fields are present
  const errors = [];
  if (!validated.tech_stack) errors.push('缺少 tech_stack');
  if (!validated.attack_surface) errors.push('缺少 attack_surface');
  if (!validated.risk_assessment) errors.push('缺少 risk_assessment');
  if (!validated.recommended_strategy) errors.push('缺少 recommended_strategy');

  const analysisResult = {
    target,
    target_class: targetClass,
    scan_types: scanTypesRun,
    findings_count: results.length,
    ...validated,
    _raw_fields: Object.keys(parsed),
  };

  if (errors.length > 0) {
    return { ok: true, data: analysisResult, warnings: errors };
  }

  return { ok: true, data: analysisResult };
}

export default { analyzeScanResults };
