/**
 * payloadGenerator.js — AI 载荷生成服务
 *
 * 使用 LLM 根据目标分类、MITRE 技术等参数生成结构化载荷。
 * 生成的载荷存入 generated_payloads 表，需教师审核后才可用于 Playbook。
 */

import { randomUUID } from 'crypto';
import { callLlm } from './llmClient.js';
import { getPayloadList, getPayloadById } from './payloadLoader.js';

/**
 * 生成载荷
 * @param {object} params
 * @param {string} params.category - 载荷分类（中文），如 "SQL/NoSQL注入"
 * @param {string} params.target_type - 目标类型: 'web' | 'intranet' | 'tool'
 * @param {string} [params.technique_id] - MITRE 技术ID，如 "T1190"
 * @param {object} [params.constraints] - 约束条件
 * @param {string} [params.createdBy] - 创建者
 * @param {object} params.db - better-sqlite3 Database
 * @returns {{ ok: boolean, payload?: object, error?: string }}
 */
export async function generatePayload({ category, target_type, technique_id, constraints, createdBy, db }) {
  // 1. 获取同类载荷作为 few-shot 示例
  const existingPayloads = getPayloadList({ category, type: target_type, db });
  const examples = existingPayloads.slice(0, 3).map(p => {
    const full = getPayloadById(p.id, db);
    if (!full) return null;
    return {
      id: full.id,
      name: full.name,
      category: full.category,
      execution: (full.execution || full.commands || []).slice(0, 2).map(e => ({
        title: e.title?.zh || e.name?.zh || '',
        command: (e.command || '').substring(0, 200),
      })),
    };
  }).filter(Boolean);

  // 2. 构建 LLM prompt
  const prompt = buildPayloadGenPrompt({ category, target_type, technique_id, constraints, examples });

  // 3. 调用 LLM
  let llmResponse;
  try {
    const messages = [
      { role: 'system', content: '你是一个渗透测试载荷生成专家。根据给定的分类和示例，生成结构化的攻击载荷。输出必须是有效的JSON。' },
      { role: 'user', content: prompt },
    ];
    const result = await callLlm(messages, { temperature: 0.7, maxTokens: 2000 });
    // callLlm returns { ok, content/error }
    if (!result.ok) {
      return { ok: false, error: result.error || 'LLM call failed' };
    }
    llmResponse = result.content;
  } catch (err) {
    return { ok: false, error: `LLM call failed: ${err.message}` };
  }

  // 4. 解析 LLM 输出
  let generatedPayload;
  try {
    // Try to extract JSON from markdown code block
    const jsonMatch = llmResponse.match(/```json\s*([\s\S]*?)```/) ||
                      llmResponse.match(/```\s*([\s\S]*?)```/) ||
                      [null, llmResponse];
    generatedPayload = JSON.parse(jsonMatch[1].trim());
  } catch (err) {
    return { ok: false, error: `Failed to parse LLM output as JSON: ${err.message}` };
  }

  // 5. 验证并标准化载荷结构
  if (!generatedPayload.name || !generatedPayload.execution) {
    return { ok: false, error: 'Generated payload missing required fields (name, execution)' };
  }

  const payloadId = `ai_${category.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase()}_${randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  const normalizedPayload = {
    id: payloadId,
    name: generatedPayload.name,
    description: generatedPayload.description || { zh: `AI生成的${category}载荷`, en: `AI-generated ${category} payload` },
    category: generatedPayload.category || { zh: category, en: category },
    tags: generatedPayload.tags || [category, 'ai-generated'],
    execution: generatedPayload.execution,
    wafBypass: generatedPayload.wafBypass || [],
    edrBypass: generatedPayload.edrBypass || [],
    opsecTips: generatedPayload.opsecTips || [],
    prerequisites: generatedPayload.prerequisites || [],
    references: generatedPayload.references || [],
    tutorial: generatedPayload.tutorial || null,
  };

  // 6. 存入 DB
  try {
    db.prepare(`
      INSERT INTO generated_payloads (payload_id, name, category, payload_type, payload_data, source, mitre_technique, import_status, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, 'ai_generated', ?, 'candidate', ?, ?)
    `).run(
      payloadId,
      normalizedPayload.name?.zh || normalizedPayload.name?.en || JSON.stringify(normalizedPayload.name),
      category,
      target_type,
      JSON.stringify(normalizedPayload),
      technique_id || null,
      createdBy || 'system',
      now
    );
  } catch (err) {
    return { ok: false, error: `DB insert failed: ${err.message}` };
  }

  return { ok: true, payload: { ...normalizedPayload, _type: 'ai_generated', import_status: 'candidate' } };
}

/**
 * 构建 LLM 载荷生成 prompt
 */
function buildPayloadGenPrompt({ category, target_type, technique_id, constraints, examples }) {
  const lines = [];

  lines.push(`请生成一个"${category}"类型的渗透测试载荷。`);
  lines.push(`目标类型: ${target_type}`);
  if (technique_id) {
    lines.push(`MITRE ATT&CK 技术: ${technique_id}`);
  }
  if (constraints && Object.keys(constraints).length > 0) {
    lines.push(`约束条件: ${JSON.stringify(constraints)}`);
  }
  lines.push('');

  if (examples.length > 0) {
    lines.push('## 同类载荷示例（供参考，不要照搬）');
    lines.push('');
    for (const ex of examples) {
      lines.push(`### ${ex.id}`);
      lines.push(`名称: ${JSON.stringify(ex.name)}`);
      lines.push(`分类: ${JSON.stringify(ex.category)}`);
      if (ex.execution.length > 0) {
        lines.push('执行步骤:');
        for (const e of ex.execution) {
          lines.push(`  - ${e.title}: ${e.command}`);
        }
      }
      lines.push('');
    }
  }

  lines.push('## 输出格式要求');
  lines.push('');
  lines.push('请输出JSON格式的载荷，结构如下：');
  lines.push('```json');
  lines.push(JSON.stringify({
    name: { zh: '载荷中文名', en: 'Payload English name' },
    description: { zh: '载荷描述', en: 'Payload description' },
    category: { zh: category, en: category },
    tags: ['tag1', 'tag2'],
    execution: [
      {
        title: { zh: '步骤标题', en: 'Step title' },
        command: '具体命令',
        description: { zh: '步骤说明', en: 'Step description' },
        platform: 'all',
      },
    ],
    wafBypass: [],
    edrBypass: [],
    opsecTips: [{ zh: 'OPSEC建议', en: 'OPSEC tip' }],
    prerequisites: [{ zh: '前置条件', en: 'Prerequisite' }],
  }, null, 2));
  lines.push('```');

  return lines.join('\n');
}
