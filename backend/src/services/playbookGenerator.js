import { getDb } from '../db/connection.js';
import { callLlm } from './llmClient.js';
import { resolveTargetProfile } from './targetProfileResolver.js';

const TOOL_LIST = [
  'nmap', 'httpx', 'nikto', 'sqlmap', 'nuclei', 'hydra', 'john',
  'dirb', 'gobuster', 'ffuf', 'whatweb', 'wpscan',
  'evil-winrm', 'netexec', 'sshpass', 'responder', 'mitm6',
  'arjun', 'cloudmapper', 'pacu', 'awscli',
];

export async function generatePlaybook(scanTaskId) {
  const db = getDb();

  // Get scan task + results
  const task = db.prepare(
    'SELECT scan_task_id, target, scan_type FROM scan_tasks WHERE scan_task_id = ?'
  ).get(scanTaskId);
  if (!task) return { ok: false, error: 'Scan task not found' };

  const results = db.prepare(
    `SELECT result_type, result_data, severity, mitre_technique_id, source_tool
     FROM scan_results WHERE scan_task_id = ? ORDER BY severity DESC LIMIT 15`
  ).all(scanTaskId);

  // Build findings summary — skip raw_output (tool output noise, not useful for playbook)
  // and truncate each entry to keep prompt within LLM context limits
  const MAX_DATA_STR_LEN = 300;
  const MAX_FINDINGS_LEN = 8000; // safety cap for total findings text

  const findingsLines = [];
  for (const r of results) {
    if (r.result_type === 'raw_output') continue; // skip raw tool output
    let dataStr = '';
    try {
      const d = JSON.parse(r.result_data || '{}');
      dataStr = Object.entries(d).map(([k, v]) => `${k}=${v}`).join(', ');
    } catch { dataStr = (r.result_data || '').slice(0, MAX_DATA_STR_LEN); }
    // Truncate per-entry to avoid blowing up prompt
    if (dataStr.length > MAX_DATA_STR_LEN) dataStr = dataStr.slice(0, MAX_DATA_STR_LEN) + '…';
    findingsLines.push(`- [${r.severity}] ${r.result_type}: ${dataStr} (tool: ${r.source_tool}, mitre: ${r.mitre_technique_id || 'N/A'})`);
  }

  let findings = findingsLines.join('\n');
  // Hard cap: if findings still too long, truncate from the end
  if (findings.length > MAX_FINDINGS_LEN) {
    findings = findings.slice(0, MAX_FINDINGS_LEN) + '\n…(更多发现已截断)';
  }

  // Resolve target class for intelligent target_type
  const targetProfile = resolveTargetProfile(task.target);
  const TARGET_CLASS_TO_TYPE = {
    dvwa: ['web_url', 'dvwa'],
    local_ip: ['web_url', 'local_ip'],
    web_url: ['web_url'],
    windows_ad: ['windows_host', 'ad_domain'],
    cloud: ['cloud'],
    subdomain: ['domain'],
    local_hash: ['local_file'],
    unknown: ['any'],
  };
  const detectedTargetTypes = TARGET_CLASS_TO_TYPE[targetProfile.target_class] || ['any'];

  const prompt = `You are a red team playbook generator. Based on the scan results below, generate a penetration testing playbook in JSON format.

Target: ${task.target}
Scan type: ${task.scan_type}
Target class: ${targetProfile.target_class} (auto-detected)

Findings:
${findings || 'No specific findings.'}

Available tools: ${TOOL_LIST.join(', ')}

Output a single JSON object with this exact structure (no markdown, no explanation):
{
  "name": "short playbook name",
  "description": "what this playbook does",
  "difficulty": "入门|初级|中级|高级",
  "baseline_group": "recon|vuln_scan|brute|exploit|web-vuln-scan",
  "target_type": ${JSON.stringify(detectedTargetTypes)},
  "mitre_techniques": ["T1xxx"],
  "steps": [
    {
      "step_index": 0,
      "step_id": "step1_xxx",
      "name": "step description",
      "tool_id": "tool name from available tools",
      "args_template": ["-flag", "<target>"],
      "description": "what this step does",
      "score": 10
    }
  ]
}

Rules:
- Steps should be ordered logically: recon first, then vuln scan, then exploit
- Use <target> as placeholder for the target in args_template
- Each step uses exactly one tool
- Generate 2-5 steps appropriate for the findings
- mitre_techniques should use real MITRE ATT&CK IDs
- Set target_type based on the detected target class: ${targetProfile.target_class}
- For windows_ad targets, use tools like netexec, evil-winrm, responder
- For cloud targets, use tools like cloudmapper, pacu
- For web targets, use tools like nmap, nikto, nuclei, sqlmap`;

  const messages = [
    { role: 'system', content: 'You are a penetration testing expert. Output only valid JSON, no markdown.' },
    { role: 'user', content: prompt },
  ];

  const result = await callLlm(messages, { temperature: 0.3, maxTokens: 4096 });
  if (!result.ok) return { ok: false, error: result.error };

  // Parse LLM response
  let playbookJson;
  try {
    const content = result.content.trim();
    const jsonStr = content.replace(/^```json?\n?/, '').replace(/\n?```$/, '').trim();
    playbookJson = JSON.parse(jsonStr);
  } catch {
    return { ok: false, error: 'Failed to parse LLM response as JSON', raw: result.content.slice(0, 500) };
  }

  // Insert into DB
  const playbookId = `gen_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO playbooks (playbook_id, name, description, difficulty, baseline_group,
      target_type, mitre_techniques, is_generated, generated_from, generated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `).run(
    playbookId, playbookJson.name, playbookJson.description,
    playbookJson.difficulty, playbookJson.baseline_group || 'recon',
    JSON.stringify(playbookJson.target_type || ['any']),
    JSON.stringify(playbookJson.mitre_techniques || []),
    scanTaskId, now
  );

  const steps = playbookJson.steps || [];
  const insertStep = db.prepare(`
    INSERT INTO playbook_steps (playbook_id, step_index, step_id, name, tool_id,
      args_template, description, score)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const step of steps) {
    insertStep.run(
      playbookId, step.step_index ?? 0, step.step_id || `step_${step.step_index}`,
      step.name, step.tool_id,
      JSON.stringify(step.args_template || []),
      step.description, step.score || 0
    );
  }

  return { ok: true, playbook_id: playbookId, name: playbookJson.name, steps_count: steps.length };
}
