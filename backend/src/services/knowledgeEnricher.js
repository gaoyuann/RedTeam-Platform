/**
 * Knowledge Graph Runtime Enricher for ReAct Engine
 *
 * Loads KG data from data/knowledge/ and builds context text
 * for injection into ReAct prompts.
 *
 * Ported from RedTeam-Edu: backend/src/knowledge/runtimeKnowledgeEnricher.js
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');

const KG_FULL_PATH = resolve(PROJECT_ROOT, 'data', 'knowledge', 'kg_full.json');
const TECHNIQUE_ZH_PATH = resolve(PROJECT_ROOT, 'data', 'knowledge', 'technique_zh.json');
const KNOWLEDGE_INDEX_PATH = resolve(PROJECT_ROOT, 'data', 'knowledge', 'knowledge_index.json');

// ── Lazy-loaded data ────────────────────────────────────────────────────
let _toolTechniqueMap = null;
let _techniqueZh = null;
let _knowledgeIndex = null;

function loadJsonSync(filePath) {
  try {
    if (existsSync(filePath)) {
      return JSON.parse(readFileSync(filePath, 'utf-8'));
    }
  } catch (err) {
    console.warn(`[knowledgeEnricher] Failed to load ${filePath}:`, err.message);
  }
  return null;
}

function loadTechniqueZh() {
  if (!_techniqueZh) {
    _techniqueZh = loadJsonSync(TECHNIQUE_ZH_PATH) || {};
  }
  return _techniqueZh;
}

function loadKnowledgeIndex() {
  if (!_knowledgeIndex) {
    _knowledgeIndex = loadJsonSync(KNOWLEDGE_INDEX_PATH) || {};
  }
  return _knowledgeIndex;
}

/**
 * Build tool → technique mapping from KG full graph.
 * Returns: { [toolId]: [{ technique_id, technique_name, zh_name, zh_desc, zh_tactic }] }
 */
function buildToolTechniqueMap() {
  if (_toolTechniqueMap) return _toolTechniqueMap;

  const kg = loadJsonSync(KG_FULL_PATH);
  if (!kg || !kg.nodes || !kg.edges) {
    console.warn('[knowledgeEnricher] KG full graph not available');
    _toolTechniqueMap = {};
    return _toolTechniqueMap;
  }

  const zhData = loadTechniqueZh();
  const nodeMap = {};
  for (const n of kg.nodes) nodeMap[n.id] = n;

  const toolMap = {};

  for (const e of kg.edges) {
    if (e.type !== 'MAPS_TO_TECHNIQUE') continue;

    const srcNode = nodeMap[e.source];
    const tgtNode = nodeMap[e.target];
    if (!srcNode || srcNode.type !== 'HexToolWrapper') continue;
    if (!tgtNode || tgtNode.type !== 'AttackTechnique') continue;

    // Normalize tool ID: strip suffixes like _scan, _enum, _probe
    let toolId = srcNode.name;
    // Try common suffixes
    for (const suffix of ['_scan', '_enum', '_probe', '_crawl', '_brute', '_exploit']) {
      if (toolId.endsWith(suffix)) {
        toolId = toolId.slice(0, -suffix.length);
        break;
      }
    }

    const eid = (tgtNode.metadata && tgtNode.metadata.external_id) || '';
    const tCode = eid || (tgtNode.id.match(/T\d{4}(?:\.\d+)?$/) || [])[0] || '';
    if (!tCode) continue;

    const zh = zhData[tCode] || {};

    if (!toolMap[toolId]) toolMap[toolId] = [];
    if (!toolMap[toolId].find(t => t.technique_id === tCode)) {
      toolMap[toolId].push({
        technique_id: tCode,
        technique_name: tgtNode.name,
        zh_name: zh.zh_name || tgtNode.name,
        zh_desc: zh.zh_desc || '',
        tactic_id: zh.tactic_id || '',
        zh_tactic: zh.zh_tactic || '',
      });
    }
  }

  _toolTechniqueMap = toolMap;
  console.log(`[knowledgeEnricher] Tool→technique map built: ${Object.keys(toolMap).length} tools`);
  return _toolTechniqueMap;
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Build KG context text for a specific tool step.
 * This text is injected into the ReAct prompt to give LLM domain knowledge.
 *
 * @param {string} toolId - e.g. 'nmap', 'nuclei', 'sqlmap'
 * @param {object} [payloadData] - optional payload metadata
 * @returns {string} - KG context text for prompt injection
 */
export function buildKGContextForStep(toolId, payloadData) {
  const toolMap = buildToolTechniqueMap();

  // Try direct match, then common suffixes
  let techniques = toolMap[toolId];
  if (!techniques) {
    for (const suffix of ['_scan', '_enum', '_probe', '_crawl', '_brute', '_exploit']) {
      techniques = toolMap[toolId + suffix];
      if (techniques) break;
    }
  }

  if (!techniques || techniques.length === 0) {
    return '';  // No KG context for this tool
  }

  const lines = [];
  lines.push(`### ${toolId} 的知识图谱上下文`);

  // Group by tactic
  const byTactic = {};
  for (const t of techniques) {
    const tactic = t.zh_tactic || '其他';
    if (!byTactic[tactic]) byTactic[tactic] = [];
    byTactic[tactic].push(t);
  }

  for (const [tactic, techs] of Object.entries(byTactic)) {
    lines.push(`**${tactic}**:`);
    for (const t of techs.slice(0, 5)) {
      lines.push(`  - ${t.technique_id} ${t.zh_name}${t.zh_desc ? ': ' + t.zh_desc.slice(0, 80) : ''}`);
    }
  }

  // Payload context
  if (payloadData) {
    lines.push('');
    lines.push(`**载荷信息**: ${payloadData.name || payloadData.id || toolId}`);
    if (payloadData.description) {
      lines.push(`  原理: ${payloadData.description.slice(0, 150)}`);
    }
    if (payloadData.defense_notes) {
      lines.push(`  防御: ${payloadData.defense_notes.slice(0, 100)}`);
    }
  }

  return lines.join('\n');
}

/**
 * Get suggested next tools based on KG attack chain.
 *
 * @param {string} toolId - current tool
 * @returns {{ current: object, suggested_tools: Array }}
 */
export function getSuggestedNextTools(toolId) {
  const toolMap = buildToolTechniqueMap();

  let techniques = toolMap[toolId];
  if (!techniques) {
    for (const suffix of ['_scan', '_enum', '_probe', '_crawl', '_brute', '_exploit']) {
      techniques = toolMap[toolId + suffix];
      if (techniques) break;
    }
  }

  if (!techniques || techniques.length === 0) {
    return { current: { toolId, techniques: [] }, suggested_tools: [] };
  }

  // Find tools that share techniques in later tactics
  const currentTacticIds = new Set(techniques.map(t => t.tactic_id));
  const suggested = [];

  for (const [tid, techs] of Object.entries(toolMap)) {
    if (tid === toolId) continue;
    // Check if this tool has techniques in a different tactic
    const hasOverlap = techs.some(t => !currentTacticIds.has(t.tactic_id));
    if (hasOverlap) {
      suggested.push({
        toolId: tid,
        techniques: techs.slice(0, 3).map(t => `${t.technique_id} ${t.zh_name}`),
      });
    }
  }

  return {
    current: { toolId, techniques: techniques.slice(0, 5) },
    suggested_tools: suggested.slice(0, 8),
  };
}

/**
 * Get tool info for frontend AI chat.
 *
 * @param {string} toolId
 * @returns {{ techniques: Array, summary: string } | null}
 */
export function getToolKGInfo(toolId) {
  const toolMap = buildToolTechniqueMap();
  const techniques = toolMap[toolId];
  if (!techniques) return null;

  return {
    techniques: techniques.slice(0, 10),
    summary: techniques.slice(0, 3).map(t => `${t.technique_id} ${t.zh_name}`).join(', '),
  };
}

/**
 * Reset cached data (for testing).
 */
export function resetCache() {
  _toolTechniqueMap = null;
  _techniqueZh = null;
  _knowledgeIndex = null;
}
