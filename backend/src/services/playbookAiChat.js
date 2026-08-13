/**
 * PlaybookAiChat - Multi-turn AI chat for playbook generation
 * Ported from RedTeam-Edu: backend/src/hexstrike/playbookAiChat.js
 * Simplified: basic multi-turn chat with KG context injection
 */

import { callLlm } from './llmClient.js';
import { IMAGE_MAP, VIRTUAL_TOOLS } from '../tools/toolRunner.js';
import { getPayloadList, getPayloadCategories } from './payloadLoader.js';

/**
 * Build a system prompt listing available tools grouped by category
 * with MITRE technique context from knowledgeEnricher.
 */
export function buildKGSystemPrompt(db) {
  // Group tools by category
  const categories = {
    recon: { label: '侦察扫描 (Recon/Scanning)', tools: ['nmap', 'whatweb', 'gobuster', 'ffuf', 'httpx', 'amass', 'curl'] },
    vuln: { label: '漏洞扫描 (Vulnerability Scanning)', tools: ['nuclei', 'nikto', 'sqlmap'] },
    brute: { label: '暴力破解 (Brute Force)', tools: ['hydra', 'john', 'hashcat'] },
    exploit: { label: '利用/横向移动 (Exploit/Lateral)', tools: ['netexec', 'evil-winrm', 'ssh-exec', 'rpcclient'] },
    web: { label: 'Web工具 (Web Tools)', tools: ['arjun', 'python3', 'web-brute'] },
    credential: { label: '凭证窃取 (Credential Access)', tools: ['responder', 'mitm6'] },
    cloud: { label: '云安全 (Cloud)', tools: ['cloudmapper', 'pacu'] },
    system: { label: '系统工具 (System)', tools: ['system-tools', 'cat', 'whoami', 'id', 'uname', 'ping', 'netstat'] },
  };

  const lines = [];
  lines.push('# 可用的渗透测试工具');
  lines.push('');
  lines.push('你是一个渗透测试Playbook生成助手。根据用户的扫描结果和需求，生成结构化的渗透测试执行方案。');
  lines.push('');
  lines.push('## 可用工具列表');
  lines.push('');

  for (const [key, cat] of Object.entries(categories)) {
    const available = cat.tools.filter(t => IMAGE_MAP[t]);
    if (available.length === 0) continue;
    lines.push(`### ${cat.label}`);
    for (const toolId of available) {
      const image = IMAGE_MAP[toolId];
      const kgInfo = getToolKgSnippet(toolId);
      if (kgInfo) {
        lines.push(`- \`${toolId}\` (镜像: ${image}) — ${kgInfo}`);
      } else {
        lines.push(`- \`${toolId}\` (镜像: ${image})`);
      }
    }
    lines.push('');
  }

  lines.push('## 输出格式');
  lines.push('');
  lines.push('请以JSON格式输出Playbook，包含以下字段：');
  lines.push('- `id`: Playbook的唯一标识');
  lines.push('- `name`: Playbook名称');
  lines.push('- `description`: 简要描述');
  lines.push('- `steps`: 步骤数组，每步包含：');
  lines.push('  - `step_id`: 步骤标识');
  lines.push('  - `name`: 步骤名称');
  lines.push('  - `tool_id`: 工具ID（必须来自上述可用工具列表）');
  lines.push('  - `args_template`: 参数模板数组（字符串数组）');
  lines.push('  - `payload_id`: 载荷ID（可选，从下方载荷列表中选择）');
  lines.push('  - `description`: 步骤说明');
  lines.push('');

  // ── 载荷摘要注入 ──────────────────────────────────────────────────────
  try {
    const categories = getPayloadCategories(db);
    lines.push('## 可用载荷（Payloader）');
    lines.push('');
    lines.push('每个步骤可选择绑定一个载荷（payload_id），载荷提供攻击方法、绕过变体、防御信息等。');
    lines.push('如果步骤的 tool_id 对应的载荷存在，**必须**设置 payload_id。');
    lines.push('');

    for (const [type, cats] of Object.entries(categories)) {
      if (!cats || cats.length === 0) continue;
      const typeLabel = { web: 'Web攻击载荷', intranet: '内网渗透载荷', tool: '工具命令载荷', ai_generated: 'AI生成载荷' }[type] || type;
      lines.push(`### ${typeLabel}`);
      for (const cat of cats) {
        lines.push(`- **${cat.category}** (${cat.count}个)`);
      }
      lines.push('');
    }

    // List some common payload IDs for reference
    const commonPayloads = getPayloadList({ keyword: '', db });
    const sampleIds = commonPayloads.slice(0, 30).map(p => `\`${p.id}\``).join(', ');
    lines.push(`常用载荷ID示例: ${sampleIds}${commonPayloads.length > 30 ? ' ...' : ''}`);
    lines.push('');
  } catch (e) {
    // Non-fatal: payload data may not be available
  }

  lines.push('请将JSON放在 ```json ... ``` 代码块中输出。');
  lines.push('');

  return lines.join('\n');
}

/**
 * Get a short KG snippet for a tool, showing its MITRE technique associations.
 */
function getToolKgSnippet(toolId) {
  try {
    // knowledgeEnricher uses synchronous file reads, so dynamic import into
    // a then() is fine here since buildKGSystemPrompt is not async
    // We cache the result after first call
    if (!getToolKgSnippet._cache) getToolKgSnippet._cache = {};
    if (getToolKgSnippet._cache[toolId] !== undefined) {
      return getToolKgSnippet._cache[toolId];
    }
    // Static mapping fallback (no async import needed for prompt building)
    const kgSummary = {
      nmap: 'T1046 网络服务扫描, T1595 主动扫描',
      whatweb: 'T1592 目标技术栈指纹识别',
      gobuster: 'T1595.003 目录/文件枚举',
      ffuf: 'T1595.003 模糊测试',
      nuclei: 'T1190 漏洞利用(Web/App)',
      nikto: 'T1595 主动扫描, T1190 漏洞探测',
      sqlmap: 'T1190 SQL注入漏洞利用',
      hydra: 'T1110 密码暴力破解',
      john: 'T1110.002 哈希离线破解',
      hashcat: 'T1110.002 哈希离线破解',
      netexec: 'T1021.002 SMB远程服务利用',
      'evil-winrm': 'T1021.006 WinRM远程管理',
      responder: 'T1557.001 LLMNR/NBT-NS投毒',
      arjun: 'T1595 HTTP参数发现',
      amass: 'T1596 子域名枚举',
      cloudmapper: 'T1526 云服务枚举',
      pacu: 'T1526 AWS云利用',
    };
    const result = kgSummary[toolId] || null;
    getToolKgSnippet._cache[toolId] = result;
    return result;
  } catch {
    return null;
  }
}

/**
 * Chat-based playbook generation.
 *
 * @param {object} params
 * @param {Array} params.messages - chat messages [{role, content}]
 * @param {object} [params.scanResults] - scan results for context
 * @param {object} params.db - database handle (used for scanning related queries)
 * @returns {Promise<{ok: boolean, response: string, playbook: object|null}>}
 */
export async function chatGeneratePlaybook({ messages, scanResults, db }) {
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return { ok: false, response: 'No messages provided', playbook: null };
  }

  // Build the system prompt (pass db so AI-generated payloads are included)
  const systemPrompt = buildKGSystemPrompt(db);

  // Add scan results context if provided
  let userContext = '';
  if (scanResults) {
    userContext = buildScanContext(scanResults);
  }

  // Construct the full messages array
  const llmMessages = [
    { role: 'system', content: systemPrompt },
  ];

  // Add scan context as a system-level message if present
  if (userContext) {
    llmMessages.push({ role: 'system', content: `## 扫描结果上下文\n${userContext}` });
  }

  // Add the user's conversation history
  for (const msg of messages) {
    if (msg.role === 'user' || msg.role === 'assistant') {
      llmMessages.push({ role: msg.role, content: msg.content });
    } else if (msg.role === 'system') {
      // Include any system messages from the caller
      llmMessages.push({ role: 'system', content: msg.content });
    }
  }

  // Call the LLM
  const llmResult = await callLlm(llmMessages, {
    temperature: 0.5,
    maxTokens: 8192,
    timeoutMs: 180000,
  });

  if (!llmResult.ok) {
    return { ok: false, response: `LLM调用失败: ${llmResult.error}`, playbook: null };
  }

  const response = llmResult.content;

  // Try to extract playbook JSON from the response
  const playbook = extractPlaybookJson(response);

  return {
    ok: true,
    response,
    playbook,
  };
}

/**
 * Build scan context text from scan results for injection into the chat.
 */
function buildScanContext(scanResults) {
  const lines = [];

  if (scanResults.target) {
    lines.push(`目标: ${scanResults.target}`);
  }

  if (scanResults.ports && Array.isArray(scanResults.ports)) {
    lines.push(`开放端口: ${scanResults.ports.map(p => `${p.port}/${p.service || 'unknown'}`).join(', ')}`);
  }

  if (scanResults.services && Array.isArray(scanResults.services)) {
    lines.push(`检测到的服务: ${scanResults.services.map(s => `${s.name} ${s.version || ''}`).join(', ')}`);
  }

  if (scanResults.technologies && Array.isArray(scanResults.technologies)) {
    lines.push(`Web技术栈: ${scanResults.technologies.join(', ')}`);
  }

  if (scanResults.findings && Array.isArray(scanResults.findings)) {
    lines.push(`发现项 (${scanResults.findings.length}条):`);
    for (const f of scanResults.findings.slice(0, 20)) {
      lines.push(`  - [${f.severity || 'INFO'}] ${f.name || f.title}: ${(f.description || '').substring(0, 120)}`);
    }
  }

  if (scanResults.summary) {
    lines.push(`扫描概要: ${scanResults.summary}`);
  }

  return lines.join('\n');
}

/**
 * Extract playbook JSON from LLM response.
 * Tries ```json ... ``` blocks first, then bare JSON.
 *
 * @param {string} text - LLM response text
 * @returns {object|null} - extracted playbook object or null
 */
export function extractPlaybookJson(text) {
  if (!text) return null;

  // Try fenced code blocks with json
  const jsonBlockMatch = text.match(/```json\s*([\s\S]*?)```/);
  if (jsonBlockMatch) {
    try {
      const obj = JSON.parse(jsonBlockMatch[1].trim());
      if (obj && obj.id && Array.isArray(obj.steps)) {
        return normalizePlaybook(obj);
      }
    } catch {
      // Fall through
    }
  }

  // Try any fenced code block
  const anyBlockMatch = text.match(/```\s*([\s\S]*?)```/);
  if (anyBlockMatch) {
    try {
      const obj = JSON.parse(anyBlockMatch[1].trim());
      if (obj && obj.id && Array.isArray(obj.steps)) {
        return normalizePlaybook(obj);
      }
    } catch {
      // Fall through
    }
  }

  // Try bare JSON (find first { ... } that looks like a playbook)
  try {
    const obj = JSON.parse(text.trim());
    if (obj && obj.id && Array.isArray(obj.steps)) {
      return normalizePlaybook(obj);
    }
  } catch {
    // Fall through
  }

  // Try to find a JSON object in the text by scanning for braces
  const braceStart = text.indexOf('{');
  if (braceStart >= 0) {
    try {
      const candidate = text.substring(braceStart);
      const obj = JSON.parse(candidate);
      if (obj && obj.id && Array.isArray(obj.steps)) {
        return normalizePlaybook(obj);
      }
    } catch {
      // Fall through
    }
  }

  return null;
}

/**
 * Normalize a playbook object: ensure step properties, add defaults.
 */
function normalizePlaybook(pb) {
  if (!pb.steps) return pb;

  pb.steps = pb.steps.map((step, idx) => ({
    step_id: step.step_id || step.id || `step_${idx}`,
    name: step.name || step.tool_id || `Step ${idx + 1}`,
    tool_id: step.tool_id,
    args_template: step.args_template || step.args || [],
    payload_id: step.payload_id || null,
    description: step.description || '',
    optional: step.optional !== undefined ? step.optional : true,
    score: step.score || 0,
    expected_mitre: step.expected_mitre || [],
  }));

  return pb;
}

