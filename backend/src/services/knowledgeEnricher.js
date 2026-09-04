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
const OWASP_TOP10_PATH = resolve(PROJECT_ROOT, 'data', 'knowledge', 'owasp_top10_2021.json');

// ── Lazy-loaded data ────────────────────────────────────────────────────
let _toolTechniqueMap = null;
let _techniqueZh = null;
let _knowledgeIndex = null;
let _owaspTop10 = null;

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

function loadOwaspTop10() {
  if (!_owaspTop10) {
    _owaspTop10 = loadJsonSync(OWASP_TOP10_PATH);
    if (!_owaspTop10) {
      console.warn('[knowledgeEnricher] OWASP Top 10 knowledge not available');
      _owaspTop10 = [];
    }
  }
  return _owaspTop10;
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
 * Build OWASP Top 10 context from a risk assessment object.
 *
 * Maps risk assessment categories (e.g., 'injection', 'access_control', 'auth')
 * to the corresponding OWASP knowledge entries and returns a formatted context string
 * for injection into ReAct prompts.
 *
 * @param {object} riskAssessment - Object with category labels and severity info
 *   e.g. { categories: ['injection', 'access_control'], severity: 'high', details: '...' }
 * @returns {string} - OWASP context text for prompt injection
 */
export function buildOwaspContext(riskAssessment) {
  const owasp = loadOwaspTop10();
  if (!owasp || owasp.length === 0) return '';

  if (!riskAssessment || !riskAssessment.categories || riskAssessment.categories.length === 0) {
    return '';
  }

  const categoryMap = {
    'injection': ['A03:2021'],
    'sql_injection': ['A03:2021'],
    'command_injection': ['A03:2021'],
    'xss': ['A03:2021'],
    'access_control': ['A01:2021'],
    'authorization': ['A01:2021'],
    'idor': ['A01:2021'],
    'cryptography': ['A02:2021'],
    'encryption': ['A02:2021'],
    'ssl_tls': ['A02:2021'],
    'design': ['A04:2021'],
    'design_flaw': ['A04:2021'],
    'misconfiguration': ['A05:2021'],
    'config': ['A05:2021'],
    'hardening': ['A05:2021'],
    'outdated': ['A06:2021'],
    'dependency': ['A06:2021'],
    'cve': ['A06:2021'],
    'authentication': ['A07:2021'],
    'auth': ['A07:2021'],
    'identity': ['A07:2021'],
    'integrity': ['A08:2021'],
    'deserialization': ['A08:2021'],
    'supply_chain': ['A08:2021'],
    'logging': ['A09:2021'],
    'monitoring': ['A09:2021'],
    'ssrf': ['A10:2021'],
    'server_side_request_forgery': ['A10:2021'],
  };

  const matchedIds = new Set();
  for (const cat of riskAssessment.categories) {
    const normalized = cat.toLowerCase().replace(/\s+/g, '_');
    const ids = categoryMap[normalized];
    if (ids) ids.forEach(id => matchedIds.add(id));
  }

  if (matchedIds.size === 0) return '';

  const lines = [];
  lines.push('### OWASP Top 10 2021 知识上下文');
  lines.push('');

  for (const id of ['A01:2021', 'A02:2021', 'A03:2021', 'A04:2021', 'A05:2021',
                    'A06:2021', 'A07:2021', 'A08:2021', 'A09:2021', 'A10:2021']) {
    if (!matchedIds.has(id)) continue;
    const entry = owasp.find(e => e.id === id);
    if (!entry) continue;

    lines.push(`**${entry.id} ${entry.name} / ${entry.name_zh}**`);
    lines.push(`  严重程度: ${entry.severity}`);
    lines.push(`  常用检测工具: ${entry.detection_tools.slice(0, 5).join(', ')}`);
    lines.push(`  常用攻击工具: ${entry.attack_tools.slice(0, 5).join(', ')}`);
    lines.push(`  典型场景: `);
    for (const scenario of entry.common_scenarios.slice(0, 4)) {
      lines.push(`    - ${scenario}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Build application analysis context for a specific tool step.
 *
 * Loads OWASP Top 10 knowledge and, if analysisResult contains tech_stack or
 * risk_assessment, injects relevant OWASP context. For known technologies
 * (e.g., Spring Boot, Express, Django), injects tech-specific vulnerability
 * knowledge. Returns a context string for injection into ReAct prompts.
 *
 * @param {string} toolId - e.g. 'nuclei', 'sqlmap', 'nmap'
 * @param {object} [analysisResult] - Analysis result containing tech_stack, risk_assessment
 *   e.g. {
 *     tech_stack: { frameworks: ['spring-boot 2.7', 'react 18'], os: 'linux', server: 'tomcat' },
 *     risk_assessment: { categories: ['injection', 'auth'], severity: 'high' },
 *     urls: [...]
 *   }
 * @returns {string} - Combined context text for prompt injection
 */
export function buildAppContextForStep(toolId, analysisResult) {
  const parts = [];

  // 1. OWASP context from risk assessment
  if (analysisResult && analysisResult.risk_assessment) {
    const owaspCtx = buildOwaspContext(analysisResult.risk_assessment);
    if (owaspCtx) parts.push(owaspCtx);
  }

  // 2. Technology-specific vulnerability knowledge
  if (analysisResult && analysisResult.tech_stack) {
    const tech = analysisResult.tech_stack;
    const techLines = ['### 技术栈漏洞知识'];

    // Collect all framework/server/OS info
    const frameworks = (tech.frameworks || []).map(f => f.toLowerCase());
    const allTech = new Set([
      ...frameworks,
      ...(tech.server || '').toLowerCase().split(/[\s,/]+/).filter(Boolean),
      tech.os ? tech.os.toLowerCase() : '',
    ].filter(Boolean));

    const owasp = loadOwaspTop10();

    for (const t of allTech) {
      let relevantEntries = [];

      // Spring Boot — injection, misconfiguration, SSRF
      if (t.includes('spring') || t.includes('spring-boot') || t.includes('springboot')) {
        relevantEntries = owasp.filter(e =>
          ['A03:2021', 'A05:2021', 'A10:2021'].includes(e.id)
        );
      }
      // Express/Node.js — injection, auth failures
      else if (t.includes('express') || t.includes('node') || t.includes('node.js')) {
        relevantEntries = owasp.filter(e =>
          ['A03:2021', 'A07:2021', 'A02:2021'].includes(e.id)
        );
      }
      // Django/Python — injection, deserialization
      else if (t.includes('django') || t.includes('python') || t.includes('flask')) {
        relevantEntries = owasp.filter(e =>
          ['A03:2021', 'A08:2021', 'A05:2021'].includes(e.id)
        );
      }
      // Tomcat/JBoss — misconfiguration, outdated components
      else if (t.includes('tomcat') || t.includes('jboss') || t.includes('jboss-as')) {
        relevantEntries = owasp.filter(e =>
          ['A05:2021', 'A06:2021', 'A07:2021'].includes(e.id)
        );
      }
      // Nginx/Apache — misconfiguration
      else if (t.includes('nginx') || t.includes('apache') || t.includes('httpd')) {
        relevantEntries = owasp.filter(e =>
          ['A05:2021', 'A02:2021'].includes(e.id)
        );
      }
      // Kubernetes/Docker — misconfiguration, integrity
      else if (t.includes('kubernetes') || t.includes('k8s') || t.includes('docker')) {
        relevantEntries = owasp.filter(e =>
          ['A05:2021', 'A08:2021', 'A06:2021'].includes(e.id)
        );
      }
      // Windows — authentication, access control
      else if (t.includes('windows') || t.includes('iis') || t.includes('asp.net')) {
        relevantEntries = owasp.filter(e =>
          ['A01:2021', 'A07:2021', 'A05:2021'].includes(e.id)
        );
      }

      if (relevantEntries.length > 0) {
        techLines.push(`  **${t}** 相关的 OWASP 类别:`);
        for (const entry of relevantEntries) {
          techLines.push(`    - ${entry.id} ${entry.name_zh}: ${entry.description_zh.slice(0, 80)}`);
        }
      }
    }

    if (techLines.length > 1) {
      parts.push(techLines.join('\n'));
    }
  }

  // 3. Include KG context if available (existing function)
  const kgCtx = buildKGContextForStep(toolId, analysisResult);
  if (kgCtx) parts.push(kgCtx);

  return parts.join('\n\n');
}

/**
 * Reset cached data (for testing).
 */
export function resetCache() {
  _toolTechniqueMap = null;
  _techniqueZh = null;
  _knowledgeIndex = null;
  _owaspTop10 = null;
}
