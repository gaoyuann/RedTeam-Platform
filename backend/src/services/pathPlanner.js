/**
 * PathPlanner - Generates deterministic next-step suggestions
 * Ported from RedTeam-Edu: backend/src/runs/pathPlanner.js
 */

import { getSuggestedNextTools } from './knowledgeEnricher.js';

/**
 * Infer next actions based on current run state.
 *
 * @param {object} params
 * @param {Array} params.findings - evidence records from the run
 * @param {Array} params.ruleMatches - rule engine match results
 * @param {Array} params.interventions - blue team interventions
 * @param {Array} params.recentTools - tool IDs that were recently used
 * @returns {{ actions: Array<{kind: string, title: string, reason: string, suggested: object}> }}
 */
export function inferNextActions({ findings = [], ruleMatches = [], interventions = [], recentTools = [] }) {
  const actions = [];

  // 1. Check if target is isolated (via intervention)
  const hasIsolation = interventions.some(i => i.type === 'isolate_host');
  if (hasIsolation) {
    actions.push({
      kind: 'info',
      title: '目标已被隔离',
      reason: '蓝队已对目标实施了主机隔离，无法继续渗透测试',
      suggested: null,
    });
    return { actions: actions.slice(0, 12) };
  }

  // 2. Rule-based recommendations (from rules engine matches)
  for (const match of ruleMatches) {
    const thenClause = match.then || {};
    const recs = thenClause.recommendations || [];
    for (const rec of recs) {
      const toolId = rec.suggestedTool || match.ruleId || 'unknown';
      if (!recentTools.includes(toolId)) {
        actions.push({
          kind: 'rule_recommendation',
          title: rec.title || `基于规则[${match.ruleId}]的建议`,
          reason: rec.reason || `规则匹配触发了建议`,
          suggested: {
            toolId,
            args: rec.args || [],
            ruleId: match.ruleId,
            priority: rec.priority || 50,
          },
        });
      }
    }
  }

  // 3. Check findings for clues about next steps
  const evidenceTypes = new Set(findings.map(f => f.evidence_type));

  // No findings at all → suggest initial scanning
  if (findings.length === 0) {
    actions.push({
      kind: 'scanning',
      title: '执行初始端口扫描',
      reason: '尚无任何发现，建议对目标进行Nmap端口扫描以发现开放服务',
      suggested: { toolId: 'nmap', args: ['-sV', '-T4', '<target>'], priority: 100 },
    });
  }

  // No ports found → suggest nmap
  if (!evidenceTypes.has('open_port') && findings.length > 0) {
    actions.push({
      kind: 'scanning',
      title: '执行Nmap端口扫描',
      reason: '尚未发现开放端口，建议执行服务版本检测扫描',
      suggested: { toolId: 'nmap', args: ['-sV', '-T4', '<target>'], priority: 90 },
    });
  }

  // Web ports found → suggest web reconnaissance
  const hasWebPort = findings.some(f => {
    if (f.evidence_type === 'open_port') {
      try {
        const data = typeof f.evidence_data === 'string' ? JSON.parse(f.evidence_data) : f.evidence_data;
        return data && (data.port === 80 || data.port === 443 || data.port === 8080 || data.port === 8443);
      } catch { return false; }
    }
    return false;
  });

  if (hasWebPort) {
    const webTools = [
      { toolId: 'whatweb', args: ['<target>'], reason: '识别目标Web技术栈', priority: 80 },
      { toolId: 'gobuster', args: ['dir', '-u', 'http://<target>', '-w', '/usr/share/wordlists/dirb/common.txt'], reason: '枚举Web目录和文件', priority: 75 },
    ];
    for (const wt of webTools) {
      if (!recentTools.includes(wt.toolId)) {
        actions.push({
          kind: 'web_recon',
          title: `执行${wt.toolId} Web探测`,
          reason: wt.reason,
          suggested: { ...wt, priority: wt.priority },
        });
      }
    }

    // If web tech is identified, suggest vulnerability scanning
    if (evidenceTypes.has('web_fingerprint')) {
      actions.push({
        kind: 'vuln_scan',
        title: '执行Nuclei漏洞扫描',
        reason: '已识别Web技术栈，建议使用Nuclei进行漏洞扫描',
        suggested: { toolId: 'nuclei', args: ['-u', '<target>', '-severity', 'medium,high,critical'], priority: 70 },
      });
    }
  }

  // Open ports found but no web tech identified → suggest whatweb/httpx
  if (evidenceTypes.has('open_port') && !evidenceTypes.has('web_fingerprint')) {
    actions.push({
      kind: 'fingerprint',
      title: '执行Web指纹识别',
      reason: '已发现开放端口，建议识别Web服务指纹',
      suggested: { toolId: 'whatweb', args: ['<target>'], priority: 70 },
    });
  }

  // Vulnerabilities found → suggest exploitation
  if (evidenceTypes.has('vulnerability')) {
    actions.push({
      kind: 'exploitation',
      title: '尝试漏洞利用',
      reason: '已发现漏洞，建议尝试利用获取初始访问权限',
      suggested: { toolId: 'sqlmap', args: ['-u', 'http://<target>', '--batch'], priority: 60 },
    });
    actions.push({
      kind: 'exploitation',
      title: '尝试Hydra密码爆破',
      reason: '发现漏洞后，建议对暴露的服务进行密码爆破测试',
      suggested: { toolId: 'hydra', args: ['-l', 'admin', '-P', '/usr/share/wordlists/rockyou.txt', '<target>', 'ssh'], priority: 55 },
    });
  }

  // Credentials found → suggest lateral movement
  if (evidenceTypes.has('credential_access')) {
    actions.push({
      kind: 'lateral',
      title: '尝试横向移动',
      reason: '已获取凭据，建议尝试横向移动到其他系统',
      suggested: { toolId: 'netexec', args: ['smb', '<target>', '-u', 'admin', '-p', 'obtained_password'], priority: 65 },
    });
  }

  // 4. KG-driven attack chain suggestions
  const lastTool = recentTools[recentTools.length - 1];
  if (lastTool) {
    try {
      const kgSuggestions = getSuggestedNextTools(lastTool);
      if (kgSuggestions && kgSuggestions.suggested_tools) {
        for (const st of kgSuggestions.suggested_tools) {
          if (!recentTools.includes(st.toolId) && !actions.some(a => a.suggested?.toolId === st.toolId)) {
            actions.push({
              kind: 'kg_chain',
              title: `知识图谱建议: 使用${st.toolId}`,
              reason: `基于攻击链推荐 — ${(st.techniques || []).join(', ')}`,
              suggested: { toolId: st.toolId, args: ['<target>'], priority: 50, source: 'knowledge_graph' },
            });
          }
        }
      }
    } catch {
      // KG data may not be available
    }
  }

  // Sort by priority descending, limit to 12
  return { actions: actions.slice(0, 12) };
}

/**
 * Estimate attack phase based on findings.
 * Returns one of: recon, weaponization, delivery, exploitation, installation, c2, actions_on_objectives
 */
export function estimateAttackPhase(findings = []) {
  const types = new Set(findings.map(f => f.evidence_type));

  if (types.has('lateral_movement') || types.has('credential_access')) return 'actions_on_objectives';
  if (types.has('vulnerability') || types.has('command_execution')) return 'exploitation';
  if (types.has('web_fingerprint') || types.has('dir_enum') || types.has('fuzz_result')) return 'delivery';
  if (types.has('open_port') || types.has('subdomain')) return 'recon';
  if (types.has('param_discovery')) return 'weaponization';

  return 'recon';
}
