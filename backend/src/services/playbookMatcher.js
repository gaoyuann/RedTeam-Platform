import { getDb } from '../db/connection.js';
import { checkTargetTypeCompatibility } from './targetProfileResolver.js';

const RESULT_TYPE_MAP = {
  open_port: 'recon', service_info: 'recon', http_probe: 'recon', technology_detection: 'recon',
  vulnerability: 'vuln_scan', web_vuln: 'vuln_scan', misconfiguration: 'vuln_scan',
  sql_injection: 'exploit', credential: 'brute', weak_credential: 'brute',
};
const PORT_GROUP_MAP = { 445: 'brute', 139: 'brute', 22: 'brute', 3389: 'brute',
  80: 'vuln_scan', 443: 'vuln_scan', 8080: 'vuln_scan', 8443: 'vuln_scan',
  3000: 'vuln_scan', 5000: 'vuln_scan', 3306: 'exploit', 5432: 'exploit' };
const PORT_CLASS_GROUP_MAP = {
  '22:local_ip': 'impact-demonstration', '22:linux_host': 'impact-demonstration',
  '445:windows_ad': 'windows-exploitation', '3389:windows_ad': 'windows-exploitation',
};
const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0.5 };
const WEB_TYPES = ['web', 'web_url', 'web_app', 'rest_api', 'graphql_api', 'spa_app'];

export function matchPlaybooks(scanResults, targetClass = null) {
  const db = getDb();
  const targetProfile = typeof targetClass === 'object' && targetClass !== null ? targetClass : null;
  if (targetProfile) targetClass = targetProfile.target_class;
  const confirmedDvwa = targetProfile?.application?.name === 'dvwa' && targetProfile.application.confidence >= 0.85;
  const steps = new Map();
  for (const step of db.prepare('SELECT playbook_id, tool_id, args_template FROM playbook_steps').all()) {
    if (!steps.has(step.playbook_id)) steps.set(step.playbook_id, []);
    steps.get(step.playbook_id).push(step);
  }
  const playbooks = db.prepare(`SELECT playbook_id, name, difficulty, baseline_group, mitre_techniques,
    target_type, not_suitable_for, metadata FROM playbooks WHERE is_generated = 0`).all().map(playbook => {
    const metadata = readObject(playbook.metadata);
    const targetTypes = readArray(playbook.target_type);
    const playbookSteps = steps.get(playbook.playbook_id) || [];
    const args = playbookSteps.flatMap(step => readArray(step.args_template)).join(' ');
    const requiresDvwa = (targetTypes.includes('dvwa') && !targetTypes.some(type => ['any', 'local_ip', ...WEB_TYPES].includes(type)))
      || /dvwa|\/vulnerabilities\/|\/hackable\/|security=low/i.test(args)
      || (metadata.target_class === 'dvwa' && /user_token|Login=Login/.test(args))
      || /\{\{\s*(?:sqli_url|login_url)\s*\}\}/i.test(args);
    const genericWeb = !requiresDvwa && targetTypes.some(type => WEB_TYPES.includes(type));
    return { ...playbook, targetTypes, requiresDvwa, args,
      targetClass: genericWeb && metadata.target_class === 'dvwa' ? 'web_url' : metadata.target_class,
      mitreSet: new Set(readArray(playbook.mitre_techniques)),
      tools: new Set(playbookSteps.map(step => step.tool_id)),
      notSuitableFor: readArray(playbook.not_suitable_for) };
  }).filter(playbook => (!playbook.requiresDvwa || confirmedDvwa)
    && (!targetClass || checkTargetTypeCompatibility(playbook.targetTypes, targetClass).ok)
    && !playbook.notSuitableFor.includes(targetClass));

  const signals = new Map();
  for (const result of Array.isArray(scanResults) ? scanResults : []) {
    if (['scan_error', 'raw_output'].includes(result.result_type)) continue;
    const data = readObject(result.result_data);
    if (['http_probe', 'technology_detection'].includes(result.result_type)
      && data.status_code !== undefined && (!Number.isFinite(Number(data.status_code)) || Number(data.status_code) < 200 || Number(data.status_code) >= 400)) continue;
    const severity = SEVERITY_WEIGHT[result.severity] ?? 1;
    const kind = findingKind(result, data);
    let group = RESULT_TYPE_MAP[result.result_type];
    if (result.result_type === 'open_port') {
      const port = data.port || data.port_number;
      group = PORT_CLASS_GROUP_MAP[`${port}:${targetClass}`] || PORT_GROUP_MAP[port] || group;
    }
    for (const playbook of playbooks) {
      const score = capabilityScore(playbook, kind);
      if (score > 0) addSignal(playbook.playbook_id, kind, score + severity, kindReason(kind));
      else if (kind === 'general' && group && normalizeGroup(playbook.baseline_group) === group) {
        addSignal(playbook.playbook_id, group, severity * 2, `${result.result_type} → ${group}`);
      }
      if (result.mitre_technique_id && playbook.mitreSet.has(result.mitre_technique_id)
        && (score > 0 || (kind === 'general' && group))) {
        addSignal(playbook.playbook_id, result.mitre_technique_id, severity, `MITRE ${result.mitre_technique_id}`);
      }
    }
  }

  const ranked = [];
  for (const playbook of playbooks) {
    const matches = [...(signals.get(playbook.playbook_id)?.values() || [])];
    if (!matches.length) continue;
    matches.sort((first, second) => second.score - first.score);
    let score = matches[0].score + Math.min(4, matches.slice(1).reduce((total, match) => total + match.score * 0.25, 0));
    const reasons = matches.map(match => match.reason);
    if (playbook.playbook_id === 'web_sqli_verify') reasons.push('执行前须选定带参数的具体入口，不以靶场首页代替');
    if (confirmedDvwa && playbook.requiresDvwa) {
      score += 6;
      reasons.unshift('当前扫描指纹确认 DVWA，步骤适配该靶场');
    }
    if (targetClass) {
      score += 1;
      if (playbook.targetClass === targetClass) score += 2;
      reasons.push(`目标类型兼容：${targetClass}`);
    }
    ranked.push({ playbook_id: playbook.playbook_id, name: playbook.name,
      difficulty: playbook.difficulty, baseline_group: playbook.baseline_group,
      match_reason: [...new Set(reasons)].slice(0, 3).join('; '), match_score: Math.round(score * 10) / 10 });
  }
  ranked.sort((first, second) => second.match_score - first.match_score || first.playbook_id.localeCompare(second.playbook_id));
  return ranked.slice(0, 10);

  function addSignal(playbookId, key, score, reason) {
    if (!signals.has(playbookId)) signals.set(playbookId, new Map());
    const matches = signals.get(playbookId);
    if (score > (matches.get(key)?.score || 0)) matches.set(key, { score, reason });
  }
}

function findingKind(result, data) {
  if (['http_probe', 'technology_detection'].includes(result.result_type)) return 'recon';
  if (result.result_type === 'open_port') return 'general';
  if (result.result_type === 'sql_injection') return 'sqli';
  if (['credential', 'weak_credential'].includes(result.result_type)) return 'credential';
  if (!['vulnerability', 'web_vuln', 'misconfiguration'].includes(result.result_type)) return 'general';
  if (['cloudmapper', 'pacu'].includes(result.source_tool)) return 'general';
  const text = [data.vuln_type, data.title, data.finding, data.detail, data.template, data.name, data.tags].flat().filter(Boolean).join(' ').toLowerCase();
  if (/missing.*(?:header|hsts|csp)|httponly|secure flag|x-frame-options|x-content-type-options|x-xss-protection|content-security-policy|安全.*头|响应头.*缺失/.test(text)) return 'configuration';
  if (/sql[ _-]?injection|sqli|sql[ _-]?inject|sql[ _-]?error|error[ _-]?based[ _-]?sql|sql.*syntax|sql.*注入/i.test(text)) return 'sqli';
  if (/file[ _-]?upload|arbitrary[ _-]?upload|文件上传/.test(text)) return 'upload';
  if (/\bxss\b|cross[ _-]?site[ _-]?scripting|跨站脚本/.test(text)) return 'xss';
  if (/default[ _-]?login|weak[ _-]?(?:password|credential)|弱口令|默认密码/.test(text)) return 'credential';
  if (result.result_type === 'misconfiguration' || /exposure|directory.*(?:index|listing)|phpinfo|配置|信息泄露/.test(text)) return 'configuration';
  return 'general';
}

function capabilityScore(playbook, kind) {
  const hasTool = tool => playbook.tools.has(tool);
  switch (kind) {
    case 'configuration':
      if (hasTool('nuclei') && /http-missing-security-headers|exposure,config/.test(playbook.args)) return 16;
      if (hasTool('nikto')) return 12;
      return hasTool('nuclei') && !/-tags|-id|-severity/.test(playbook.args) ? 6 : 0;
    case 'sqli':
      if (hasTool('sqlmap')) return [...playbook.tools].every(tool => ['sqlmap', 'system-tools'].includes(tool)) ? 18 : 14;
      return hasTool('nuclei') && /sqli/.test(playbook.args) ? 8 : 0;
    case 'upload':
      if (hasTool('nuclei') && /fileupload/.test(playbook.args)) return 18;
      return hasTool('upload_shell') ? 14 : 0;
    case 'xss':
      if (!hasTool('nuclei')) return 0;
      if (/\bxss\b/.test(playbook.args)) return 18;
      return !/-tags|-id/.test(playbook.args) ? 8 : 0;
    case 'credential':
      if (hasTool('hydra') || hasTool('netexec')) return 14;
      return hasTool('nuclei') && /default-login/.test(playbook.args) ? 8 : 0;
    case 'recon':
      if (normalizeGroup(playbook.baseline_group) !== 'recon') return 0;
      if (hasTool('whatweb') || hasTool('httpx')) return 10;
      return hasTool('nmap') || hasTool('gobuster') || hasTool('arjun') ? 4 : 0;
    default: return 0;
  }
}

function kindReason(kind) {
  return { configuration: '安全头/配置发现 → 配置专项扫描（不代表已验证可利用漏洞）',
    sqli: 'SQL 注入证据 → SQL 注入验证步骤', upload: '文件上传发现 → 上传专项测试',
    xss: 'XSS 发现 → Web 漏洞验证', credential: '弱口令/凭据发现 → 认证验证',
    recon: 'HTTP/服务指纹 → 侦察与技术栈识别（尚无漏洞利用证据）' }[kind];
}

function normalizeGroup(group) {
  return group === 'web-vuln-scan' ? 'vuln_scan' : group;
}

function readObject(value) {
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch { return {}; }
}

function readArray(value) {
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}
