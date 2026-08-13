/**
 * payloadLoader.js — 懒加载 Payloader 载荷数据，提供统一查询接口
 *
 * 数据来源：
 *   1. 静态载荷: data/knowledge/payloader_data.json (Payloader OSS, 305 items)
 *   2. AI 生成载荷: generated_payloads 表 (import_status='accepted')
 *
 * 移植自 RedTeam-Edu: backend/src/runtime/playbookCompiler.js L44-64
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PAYLOADER_DATA_PATH = path.join(__dirname, '..', '..', '..', 'data', 'knowledge', 'payloader_data.json');

// ── 工具 → 概念载荷映射表 ────────────────────────────────────────────────
// 当 Playbook 步骤未显式指定 payload_id 时，可根据 toolId 自动匹配概念载荷
export const TOOL_TO_CONCEPT_PAYLOADS = {
  nmap: ['port-scan'],
  hydra: ['auth-brute'],
  sqlmap: ['sqli-blind'],
  'evil-winrm': ['lateral-winrm'],
  responder: ['ntlm-relay'],
  netexec: ['pass-the-hash', 'share-enum'],
  msfvenom: ['evasion-shellcode-encrypt', 'metasploit'],
  nikto: ['nikto'],
  nuclei: ['nuclei'],
  gobuster: ['gobuster'],
  ffuf: ['ffuf'],
  amass: ['amass'],
  httpx: ['httpx'],
  whatweb: ['whatweb'],
  john: ['john'],
  hashcat: ['hashcat'],
  arjun: ['arjun'],
};

// ── 懒加载索引 ──────────────────────────────────────────────────────────
let _payloadIndex = null;  // payload_id → payload object
let _categoryStats = null; // 分类统计缓存

/**
 * 懒加载 Payloader 数据索引（静态载荷 + AI 生成载荷）
 * @param {object} [db] - better-sqlite3 Database (可选，用于加载 AI 生成载荷)
 * @returns {object} payload_id → payload object map
 */
export function getPayloadIndex(db) {
  if (_payloadIndex) return _payloadIndex;

  _payloadIndex = {};

  // 1. 加载静态载荷
  try {
    if (!fs.existsSync(PAYLOADER_DATA_PATH)) {
      console.warn('[PAYLOADER] payloader_data.json not found, static payloads disabled');
    } else {
      const raw = JSON.parse(fs.readFileSync(PAYLOADER_DATA_PATH, 'utf-8'));
      const items = [
        ...(raw.webPayloads || []).map(p => ({ ...p, _type: 'web' })),
        ...(raw.intranetPayloads || []).map(p => ({ ...p, _type: 'intranet' })),
        ...(raw.toolCommands || []).map(p => ({ ...p, _type: 'tool' })),
      ];
      for (const p of items) {
        _payloadIndex[p.id] = p;
      }
      console.log(`[PAYLOADER] Static index loaded: ${items.length} payloads`);
    }
  } catch (err) {
    console.warn('[PAYLOADER] Static index load failed:', err.message);
  }

  // 2. 加载 AI 生成载荷（已审核通过的）
  if (db) {
    try {
      const rows = db.prepare(
        "SELECT payload_id, payload_data FROM generated_payloads WHERE import_status = 'accepted'"
      ).all();
      for (const row of rows) {
        try {
          const payload = JSON.parse(row.payload_data);
          _payloadIndex[row.payload_id] = { ...payload, _type: 'ai_generated', _source: 'ai' };
        } catch { /* skip malformed */ }
      }
      if (rows.length > 0) {
        console.log(`[PAYLOADER] AI-generated index loaded: ${rows.length} payloads`);
      }
    } catch (err) {
      // Table may not exist yet (before migration 002)
      if (!err.message.includes('no such table')) {
        console.warn('[PAYLOADER] AI-generated index load failed:', err.message);
      }
    }
  }

  return _payloadIndex;
}

/**
 * 强制刷新索引（用于新增 AI 生成载荷后）
 */
export function refreshPayloadIndex() {
  _payloadIndex = null;
  _categoryStats = null;
}

/**
 * 获取单个载荷
 * @param {string} id - payload_id
 * @param {object} [db] - DB instance
 * @returns {object|null}
 */
export function getPayloadById(id, db) {
  const index = getPayloadIndex(db);
  return index[id] || null;
}

/**
 * 获取载荷列表（轻量，支持过滤）
 * @param {object} [options]
 * @param {string} [options.category] - 按分类过滤（中文分类名）
 * @param {string} [options.type] - 按类型过滤: 'web' | 'intranet' | 'tool' | 'ai_generated'
 * @param {string} [options.keyword] - 按关键词搜索（id/name/tags）
 * @param {object} [options.db] - DB instance
 * @returns {Array<{id, name, category, tags, type}>}
 */
export function getPayloadList({ category, type, keyword, db } = {}) {
  const index = getPayloadIndex(db);
  const results = [];

  for (const [id, payload] of Object.entries(index)) {
    // Type filter
    if (type && payload._type !== type) continue;

    // Category filter
    if (category) {
      const catZh = payload.category?.zh || payload.category || '';
      if (catZh !== category) continue;
    }

    // Keyword filter
    if (keyword) {
      const kw = keyword.toLowerCase();
      const nameZh = (payload.name?.zh || payload.name || '').toLowerCase();
      const nameEn = (payload.name?.en || '').toLowerCase();
      const tags = (payload.tags || []).join(' ').toLowerCase();
      const idLower = id.toLowerCase();
      if (!idLower.includes(kw) && !nameZh.includes(kw) && !nameEn.includes(kw) && !tags.includes(kw)) {
        continue;
      }
    }

    results.push({
      id,
      name: payload.name?.zh || payload.name?.en || payload.name || id,
      nameEn: payload.name?.en || '',
      category: payload.category?.zh || payload.category || '',
      categoryEn: payload.category?.en || '',
      tags: payload.tags || [],
      type: payload._type,
      toolHint: payload._type === 'tool' ? id : '',
    });
  }

  return results;
}

/**
 * 获取载荷分类统计
 * @param {object} [db] - DB instance
 * @returns {{web: Array<{category, count}>, intranet: Array<{category, count}>, tool: Array<{category, count}>}}
 */
export function getPayloadCategories(db) {
  if (_categoryStats) return _categoryStats;

  const index = getPayloadIndex(db);
  const stats = { web: {}, intranet: {}, tool: {}, ai_generated: {} };

  for (const payload of Object.values(index)) {
    const type = payload._type || 'unknown';
    const cat = payload.category?.zh || payload.category || '其他';
    if (!stats[type]) stats[type] = {};
    stats[type][cat] = (stats[type][cat] || 0) + 1;
  }

  _categoryStats = {
    web: Object.entries(stats.web || {}).map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count),
    intranet: Object.entries(stats.intranet || {}).map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count),
    tool: Object.entries(stats.tool || {}).map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count),
    ai_generated: Object.entries(stats.ai_generated || {}).map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count),
  };

  return _categoryStats;
}

/**
 * 从载荷对象提取结构化 payload_data（用于编译和前端展示）
 * @param {object} payload - 原始载荷对象
 * @returns {object} 结构化 payload_data
 */
export function extractPayloadData(payload) {
  const execSteps = payload.execution || payload.commands || [];
  const primaryExec = execSteps.length > 0 ? execSteps[0] : null;

  return {
    id: payload.id,
    name: payload.name,
    category: payload.category,
    description: payload.description,
    tags: payload.tags,
    execution_count: execSteps.length,
    primary_content: primaryExec ? (primaryExec.command || '') : '',
    all_executions: execSteps.map(e => ({
      title: e.title?.zh || e.title?.en || e.name?.zh || e.name?.en || '',
      command: e.command || '',
      platform: e.platform || 'all',
    })),
    bypass_variants: [
      ...(payload.wafBypass || []),
      ...(payload.edrBypass || []),
    ].map(b => ({
      title: b.title?.zh || b.title?.en || b.title || '',
      command: b.command || '',
      description: b.description?.zh || b.description?.en || b.description || '',
    })),
    defense: payload.tutorial ? (payload.tutorial.mitigation || {}) : {},
    opsec_tips: payload.opsecTips || [],
    prerequisites: payload.prerequisites || [],
    references: payload.references || [],
    tutorial: payload.tutorial || null,
  };
}

/**
 * 构建 payload_context 文本（用于 LLM 注入）
 * @param {object} payload - 原始载荷对象
 * @param {object} payloadData - extractPayloadData() 的结果
 * @returns {string}
 */
export function buildPayloadContext(payload, payloadData) {
  const bypassCmds = payloadData.bypass_variants
    .map(b => `  - ${b.title}: ${(b.command || '').substring(0, 120)}`)
    .join('\n');
  const defenseZh = payloadData.defense?.zh || '';
  const principlesZh = payload.description?.zh || '';
  const opsecLines = (payload.opsecTips || [])
    .map(t => `  - ${t.zh || t.en || t}`)
    .join('\n');

  return [
    `【载荷原理】${principlesZh}`,
    defenseZh ? `【防御手段】${defenseZh}` : '',
    bypassCmds ? `【绕过变体(WAF/EDR Bypass)】\n${bypassCmds}` : '',
    opsecLines ? `【OPSEC建议】\n${opsecLines}` : '',
  ].filter(Boolean).join('\n\n');
}

/**
 * 获取工具到概念载荷的映射
 * @returns {object}
 */
export function getToolToConceptMap() {
  return TOOL_TO_CONCEPT_PAYLOADS;
}

/**
 * 为工具自动匹配最佳载荷 ID
 * @param {string} toolId - 工具 ID
 * @param {object} [db] - DB instance
 * @returns {string|null} 最佳 payload_id
 */
export function autoMatchPayload(toolId, db) {
  const index = getPayloadIndex(db);

  // Layer 1: 概念载荷映射（优先，方法论更丰富）
  const conceptIds = TOOL_TO_CONCEPT_PAYLOADS[toolId] || [];
  for (const cid of conceptIds) {
    if (index[cid]) return cid;
  }

  // Layer 2: toolId 精确匹配 toolCommand 载荷（fallback）
  if (index[toolId]) {
    return toolId;
  }

  return null;
}
