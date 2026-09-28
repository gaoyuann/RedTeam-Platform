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
// Reverse mappings (built by ensureAllKGMaps)
let _techniqueToToolsMap = null;
let _techniqueToMitigationsMap = null;
let _techniqueToTacticMap = null;
// Cached parsed KG JSON (avoid re-parsing 5.8MB file)
let _kgCache = null;

function loadKG() {
  if (!_kgCache) {
    _kgCache = loadJsonSync(KG_FULL_PATH);
  }
  return _kgCache;
}

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

  const kg = loadKG();
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

// ── Ensure all KG-derived reverse mappings are built ───────────────────
/**
 * Build reverse mappings: technique→tools, technique→mitigations, technique→tactic.
 * Ported from old RedTeam-Edu runtimeKnowledgeEnricher.js ensureAllKGMaps().
 */
function ensureAllKGMaps() {
  if (_techniqueToToolsMap && _techniqueToMitigationsMap && _techniqueToTacticMap) return;

  const toolMap = buildToolTechniqueMap();
  const zhData = loadTechniqueZh();

  // technique → tools (reverse from toolMap)
  _techniqueToToolsMap = {};
  for (const [toolName, techniques] of Object.entries(toolMap)) {
    for (const t of techniques) {
      if (!_techniqueToToolsMap[t.technique_id]) _techniqueToToolsMap[t.technique_id] = [];
      if (!_techniqueToToolsMap[t.technique_id].find(x => x.tool_name === toolName)) {
        _techniqueToToolsMap[t.technique_id].push({
          tool_name: toolName,
          technique_id: t.technique_id,
          zh_name: t.zh_name,
          zh_tactic: t.zh_tactic,
        });
      }
    }
  }

  // technique → tactic (from zhData)
  _techniqueToTacticMap = {};
  for (const [tCode, data] of Object.entries(zhData)) {
    if (data.tactic_id) {
      _techniqueToTacticMap[tCode] = data.tactic_id;
    }
  }

  // technique → mitigations (from KG MITIGATED_BY edges)
  _techniqueToMitigationsMap = {};
  const kg = loadKG();
  if (kg && kg.nodes && kg.edges) {
    const nodeMap = {};
    for (const n of kg.nodes) nodeMap[n.id] = n;

    for (const e of kg.edges) {
      if (e.type !== 'MITIGATED_BY') continue;
      const srcNode = nodeMap[e.source];
      const tgtNode = nodeMap[e.target];
      if (!srcNode || srcNode.type !== 'AttackTechnique') continue;
      if (!tgtNode || tgtNode.type !== 'AttackMitigation') continue;

      const tCode = (srcNode.id.match(/T\d{4}(?:\.\d+)?$/) || [])[0] || '';
      if (!tCode) continue;

      if (!_techniqueToMitigationsMap[tCode]) _techniqueToMitigationsMap[tCode] = [];
      if (!_techniqueToMitigationsMap[tCode].find(m => m.mitigation_id === tgtNode.id)) {
        _techniqueToMitigationsMap[tCode].push({
          mitigation_id: tgtNode.id,
          mitigation_name: tgtNode.name,
          description: (tgtNode.description || '').substring(0, 200),
        });
      }
    }
  }

  console.log(`[knowledgeEnricher] All KG maps built: ${Object.keys(_techniqueToToolsMap).length} tech→tools, ${Object.keys(_techniqueToMitigationsMap).length} tech→mitigations, ${Object.keys(_techniqueToTacticMap).length} tech→tactic`);
}

// ── Teaching explanations for core ATT&CK techniques ──────────────────
const TECHNIQUE_EXPLANATIONS = {
  T1046: {
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    description: '攻击者通过扫描目标网络，发现开放的端口和服务，以识别可攻击的入口点。',
    teaching_note: '这是渗透测试侦察阶段的核心技术，nmap 等工具通过 TCP/UDP 探测来枚举服务。',
  },
  T1595: {
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    description: '攻击者主动发送探测包来收集目标信息，包括端口扫描、漏洞扫描和 Web 爬取。',
    teaching_note: '主动扫描会在目标网络留下明显流量特征，蓝队可通过 IDS/IPS 检测到此类行为。',
  },
  T1190: {
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: '利用面向公网的应用程序漏洞（如 SQL 注入、命令注入、文件包含）获取初始访问权限。',
    teaching_note: 'Web 应用漏洞是最常见的初始访问向量，nuclei/sqlmap 等工具可自动化检测。',
  },
  T1110: {
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: '通过暴力破解或字典攻击尝试获取有效凭据，包括密码喷洒和凭据填充。',
    teaching_note: '弱密码策略是暴力破解成功的主要原因，hydra 等工具支持多协议暴力破解。',
  },
  T1590: {
    name: 'Gather Victim Network Information',
    tactic: 'Reconnaissance',
    description: '收集目标网络的基础设施信息，包括 IP 段、域名、ASN 等，为后续攻击做准备。',
    teaching_note: 'amass/subfinder 等工具可被动或主动收集目标的网络信息。',
  },
  T1592: {
    name: 'Gather Victim Host Information',
    tactic: 'Reconnaissance',
    description: '收集目标主机的技术信息，包括操作系统、Web 框架、服务版本等。',
    teaching_note: 'whatweb/wpscan 等工具通过 HTTP 响应头和页面特征识别目标技术栈。',
  },
  T1611: {
    name: 'Escape to Host',
    tactic: 'Privilege Escalation',
    description: '从容器或虚拟机环境逃逸到宿主机，获取更高权限。',
    teaching_note: 'trivy/kube-hunter 等工具可检测容器配置错误和已知逃逸漏洞。',
  },
};

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

  // Tactic phase identification
  const tacticNames = [...new Set(techniques.map(t => t.zh_tactic).filter(Boolean))];
  if (tacticNames.length > 0) {
    lines.push(`当前工具 ${toolId} 属于以下 ATT&CK 战术阶段：${tacticNames.join('、')}`);
  }

  // Group by tactic
  const byTactic = {};
  for (const t of techniques) {
    const tactic = t.zh_tactic || '其他';
    if (!byTactic[tactic]) byTactic[tactic] = [];
    byTactic[tactic].push(t);
  }

  lines.push('该工具对应的 MITRE ATT&CK 技术：');
  for (const [tactic, techs] of Object.entries(byTactic)) {
    lines.push(`**${tactic}**:`);
    for (const t of techs.slice(0, 5)) {
      lines.push(`  - ${t.technique_id} ${t.zh_name}${t.zh_desc ? ': ' + t.zh_desc.slice(0, 80) : ''}`);
    }
  }

  // Mitigation summary (top 3) — let LLM understand defense perspective
  ensureAllKGMaps();
  const techIds = techniques.map(t => t.technique_id);
  const mitigations = getMitigationsForTechniques(techIds);
  if (mitigations.length > 0) {
    lines.push('');
    lines.push('**缓解措施**（蓝队视角）:');
    for (const m of mitigations.slice(0, 3)) {
      lines.push(`  - ${m.mitigation_name}${m.description ? ': ' + m.description.slice(0, 80) : ''}`);
    }
  }

  // Teaching suggestions based on tactic phase
  const allTactics = new Set(techniques.map(t => t.tactic_id).filter(Boolean));
  if (allTactics.has('TA0043')) {
    lines.push('\n教学建议：此步骤执行侦察任务。完成后，考虑进行漏洞扫描或 Web 目录枚举等后续步骤。');
  } else if (allTactics.has('TA0007')) {
    lines.push('\n教学建议：此步骤执行信息发现任务。根据发现的端口/服务，考虑针对性的漏洞利用或凭据测试。');
  } else if (allTactics.has('TA0001')) {
    lines.push('\n教学建议：此步骤执行初始访问任务。成功后考虑进行持久化或权限提升。');
  } else if (allTactics.has('TA0004')) {
    lines.push('\n教学建议：此步骤执行权限提升任务。成功后考虑进行横向移动或凭据窃取。');
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

// ── ATT&CK tactic phase order (for attack chain progression) ──────────
const TACTIC_ORDER = [
  'TA0043', // Reconnaissance
  'TA0042', // Resource Development
  'TA0001', // Initial Access
  'TA0002', // Execution
  'TA0003', // Persistence
  'TA0004', // Privilege Escalation
  'TA0005', // Defense Evasion
  'TA0006', // Credential Access
  'TA0007', // Discovery
  'TA0008', // Lateral Movement
  'TA0009', // Collection
  'TA0011', // Command and Control
  'TA0010', // Exfiltration
  'TA0040', // Impact
];

/**
 * Get suggested next tools based on KG attack chain.
 * Uses TACTIC_ORDER to recommend tools in the next 3 tactic phases.
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

  // Find the highest tactic phase of the current tool
  let maxOrder = -1;
  for (const t of techniques) {
    if (t.tactic_id) {
      const order = TACTIC_ORDER.indexOf(t.tactic_id);
      if (order > maxOrder) maxOrder = order;
    }
  }

  // Recommend tools in the next 3 tactic phases
  const nextTactics = maxOrder >= 0 && maxOrder < TACTIC_ORDER.length - 1
    ? TACTIC_ORDER.slice(maxOrder + 1, maxOrder + 4)
    : [];

  ensureAllKGMaps();

  const suggestedTools = [];
  const seenTools = new Set();

  for (const tacticId of nextTactics) {
    for (const [tCode, tTacticId] of Object.entries(_techniqueToTacticMap)) {
      if (tTacticId !== tacticId) continue;
      const tools = _techniqueToToolsMap[tCode];
      if (tools && tools.length > 0) {
        const zh = loadTechniqueZh()[tCode] || {};
        for (const tool of tools) {
          if (!seenTools.has(tool.tool_name)) {
            seenTools.add(tool.tool_name);
            suggestedTools.push({
              toolId: tool.tool_name,
              technique_id: tCode,
              zh_name: zh.zh_name || tCode,
              reason: `推荐用于下一战术阶段 (${zh.zh_tactic || tacticId})`,
            });
          }
        }
      }
    }
    if (suggestedTools.length >= 8) break;
  }

  return {
    current: {
      toolId,
      techniques: techniques.slice(0, 5).map(t => ({
        technique_id: t.technique_id,
        zh_name: t.zh_name,
        zh_tactic: t.zh_tactic,
      })),
      max_tactic_order: maxOrder,
    },
    suggested_tools: suggestedTools.slice(0, 8),
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

// ── Reverse lookup: technique → tools ─────────────────────────────────

/**
 * Get tools mapped to a given MITRE technique ID.
 * @param {string} techniqueId - e.g. "T1046"
 * @returns {Array<{tool_name, technique_id, zh_name, zh_tactic}>}
 */
export function getToolsForTechnique(techniqueId) {
  if (!techniqueId) return [];
  ensureAllKGMaps();
  return _techniqueToToolsMap[techniqueId] || [];
}

/**
 * Get tactic ID for a given technique ID.
 * @param {string} techniqueId
 * @returns {string|null}
 */
export function getTacticForTechnique(techniqueId) {
  if (!techniqueId) return null;
  ensureAllKGMaps();
  return _techniqueToTacticMap[techniqueId] || null;
}

// ── Mitigation queries ────────────────────────────────────────────────

/**
 * Get mitigations for a given MITRE technique ID.
 * Supports sub-technique → parent technique fallback (T1595.003 → T1595).
 * @param {string} techniqueId - e.g. "T1046"
 * @returns {Array<{mitigation_id, mitigation_name, description}>}
 */
export function getMitigationsForTechnique(techniqueId) {
  if (!techniqueId) return [];
  ensureAllKGMaps();

  let mitigations = _techniqueToMitigationsMap[techniqueId] || [];
  if (mitigations.length === 0 && techniqueId.includes('.')) {
    const parentId = techniqueId.split('.')[0];
    mitigations = _techniqueToMitigationsMap[parentId] || [];
  }

  return mitigations;
}

/**
 * Batch query mitigations for multiple technique IDs (deduplicated).
 * @param {string[]} techniqueIds
 * @returns {Array}
 */
export function getMitigationsForTechniques(techniqueIds) {
  if (!techniqueIds || techniqueIds.length === 0) return [];

  const allMitigations = [];
  const seen = new Set();

  for (const tid of techniqueIds) {
    const mitigations = getMitigationsForTechnique(tid);
    for (const m of mitigations) {
      if (!seen.has(m.mitigation_id)) {
        seen.add(m.mitigation_id);
        allMitigations.push({ ...m, triggered_by_technique: tid });
      }
    }
  }

  return allMitigations;
}

// ── Comprehensive technique enrichment ────────────────────────────────

/**
 * Enrich a single MITRE technique with teaching explanation, related tools, and mitigations.
 * @param {string} techniqueId - e.g. "T1190"
 * @returns {object|null}
 */
export function enrichTechnique(techniqueId) {
  if (!techniqueId) return null;

  const explanation = TECHNIQUE_EXPLANATIONS[techniqueId];
  const zhData = loadTechniqueZh();
  const zh = zhData[techniqueId] || {};

  ensureAllKGMaps();
  const tools = _techniqueToToolsMap[techniqueId] || [];
  const mitigations = getMitigationsForTechnique(techniqueId);
  const tacticId = _techniqueToTacticMap[techniqueId] || null;

  if (!explanation && !zh.zh_name && tools.length === 0) {
    return null;
  }

  return {
    technique_id: techniqueId,
    technique_name: explanation?.name || zh.zh_name || techniqueId,
    tactic: explanation?.tactic || zh.zh_tactic || '',
    tactic_id: tacticId,
    description: explanation?.description || zh.zh_desc || '',
    teaching_note: explanation?.teaching_note || '',
    related_tools: tools.map(t => t.tool_name),
    mitigations: mitigations.map(m => ({
      mitigation_id: m.mitigation_id,
      name: m.mitigation_name,
      description: m.description,
    })),
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
  _techniqueToToolsMap = null;
  _techniqueToMitigationsMap = null;
  _techniqueToTacticMap = null;
  _kgCache = null;
}
