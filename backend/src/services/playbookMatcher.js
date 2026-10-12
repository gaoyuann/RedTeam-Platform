import { getDb } from '../db/connection.js';
import { checkTargetTypeCompatibility } from './targetProfileResolver.js';

const WEB_TYPES = ['web', 'web_url', 'web_app', 'rest_api', 'graphql_api', 'spa_app'];
const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0.5 };
const EVIDENCE_WEIGHT = { sqli: 36, upload: 36, xss: 36, credential: 30,
  headers: 12, cookies: 12, exposure: 18, directory: 18, vulnerability: 16,
  cloud: 16, web: 8, host: 6 };
const EVIDENCE_LABEL = { sqli: 'SQL 注入线索', upload: '文件上传线索', xss: 'XSS 线索',
  credential: '凭据/弱口令线索', headers: '安全响应头缺失', cookies: 'Cookie 安全配置',
  exposure: '敏感信息暴露', directory: '目录索引', vulnerability: '待复核漏洞发现',
  cloud: '云配置发现', web: 'HTTP/技术指纹', host: '主机/开放服务' };
const STAGE_LABEL = { reconnaissance: '入口与信息补全', supplemental_scan: '补充扫描/配置复核',
  verification: '漏洞定向验证' };
const STATUS_LABEL = { ready: '可供选择', needs_input: '需补充执行条件', already_checked: '本任务已检查' };
const IMPACT_TECHNIQUES = /^(?:T1498|T1499|T1491|T1485|T1486|T1565|T1048|T1041|T1547|T1053|T1136|T1539)(?:\.|$)/;
const IMPACT_ARGS = /--(?:os-shell|os-pwn|dump(?:-all)?|file-(?:write|read)|sql-(?:shell|query))\b|\bshutdown\b|\brm\s+-rf\b/;

export function matchPlaybooks(scanResults, targetClass = null, options = {}) {
  const db = getDb();
  const profile = typeof targetClass === 'object' && targetClass !== null ? targetClass : {};
  if (profile.target_class) targetClass = profile.target_class;
  else if (typeof targetClass === 'object') targetClass = null;
  const confirmedDvwa = profile.application?.name === 'dvwa' && profile.application.confidence >= 0.85;
  const evidence = collectEvidence(scanResults);
  if (!evidence.size) return [];
  const completed = new Set(options.completedActions || []);
  const steps = new Map();
  for (const step of db.prepare('SELECT playbook_id, tool_id, args_template FROM playbook_steps').all()) {
    if (!steps.has(step.playbook_id)) steps.set(step.playbook_id, []);
    steps.get(step.playbook_id).push(step);
  }
  const playbooks = db.prepare(`SELECT playbook_id, name, difficulty, baseline_group, mitre_techniques,
    target_type, not_suitable_for, metadata FROM playbooks WHERE is_generated = 0`).all();
  const ranked = [];
  for (const playbook of playbooks) {
    const targetTypes = readArray(playbook.target_type);
    const excluded = readArray(playbook.not_suitable_for);
    if (targetClass && (!checkTargetTypeCompatibility(targetTypes, targetClass).ok
      || excluded.includes(targetClass)
      || targetClass === 'windows_ad' && excluded.some(type => ['windows_host', 'ad_domain'].includes(type)))) continue;
    const playbookSteps = steps.get(playbook.playbook_id) || [];
    const args = playbookSteps.flatMap(step => readArray(step.args_template)).join(' ');
    const requiresDvwa = targetTypes.includes('dvwa') && !targetTypes.some(type => ['any', 'local_ip', ...WEB_TYPES].includes(type))
      || /dvwa|\/vulnerabilities\/|\/hackable\/|security=low|\{\{\s*(?:sqli_url|login_url)\s*\}\}/i.test(args)
      || readObject(playbook.metadata).target_class === 'dvwa' && /user_token|Login=Login/.test(args);
    if (requiresDvwa && !confirmedDvwa) continue;
    if (readArray(playbook.mitre_techniques).some(technique => IMPACT_TECHNIQUES.test(technique))
      || /^(?:data-exfiltration|device-control|impact-demonstration|persistence)$/.test(playbook.baseline_group)
      || IMPACT_ARGS.test(args)) continue;
    const actions = playbookSteps.map(step => describeAction(step));
    if (!actions.length || actions.some(action => !action)) continue;
    const verification = actions.filter(action => action.requiredEvidence);
    if (verification.some(action => action.requiredEvidence.some(kind => !evidence.has(kind)))) continue;
    const matches = new Map();
    let matchedActions = 0;
    let repeatedActions = 0;
    const conditions = new Set();
    for (const action of actions) {
      if (action.needsParameters && !hasParameterEntry(profile.target_url || options.target)) {
        conditions.add('须选择具体带参数 URL 或提供请求数据；不能使用靶场首页');
      }
      if (action.needsCredentials) conditions.add('须确认认证协议、登录入口及授权凭据');
      if (action.needsSession) conditions.add('须提供本次目标的有效授权会话 Cookie');
      if (action.needsReview) conditions.add('预案包含扩展探测参数，须先核对强度并采用适当的定向验证方案');
      if (action.fixedEndpoint) conditions.add('须核对预案固定端口/入口是否属于本次授权目标');
      let matched = false;
      for (const [kind, specificity] of Object.entries(action.capabilities)) {
        const signal = evidence.get(kind);
        if (!signal) continue;
        matched = true;
        const value = EVIDENCE_WEIGHT[kind] + specificity * 2 + signal.severity;
        if (value > (matches.get(kind)?.score || 0)) matches.set(kind, { score: value, ...signal });
      }
      if (!matched) continue;
      matchedActions++;
      if (completed.has(action.key)) repeatedActions++;
    }
    if (!matches.size) continue;
    const stage = verification.length ? 'verification'
      : actions.some(action => action.stage === 'supplemental_scan'
        && Object.keys(action.capabilities).some(kind => evidence.has(kind))) ? 'supplemental_scan' : 'reconnaissance';
    const sortedMatches = [...matches.entries()].sort((first, second) => second[1].score - first[1].score || first[0].localeCompare(second[0]));
    const primary = sortedMatches[0][1].score;
    const supporting = Math.min(8, sortedMatches.slice(1).reduce((total, [, signal]) => total + signal.score * 0.15, 0));
    const unrelated = actions.length - matchedActions;
    const repeatedFraction = repeatedActions / actions.length;
    const score = Math.max(0.1, primary + supporting - unrelated * 2 - (actions.length - 1) * 2 - primary * repeatedFraction * 0.75
      + (requiresDvwa ? 2 : 0));
    const alreadyChecked = repeatedActions === actions.length;
    const status = conditions.size ? 'needs_input' : alreadyChecked ? 'already_checked' : 'ready';
    const reasons = [`${STAGE_LABEL[stage]} · ${STATUS_LABEL[status]}`,
      `${sortedMatches.map(([kind]) => EVIDENCE_LABEL[kind]).join('、')} → 对应步骤能力（不代表已验证可利用漏洞）`];
    if (repeatedActions) reasons.push(`本任务已完成 ${repeatedActions}/${actions.length} 项同类检查，降低重复检查优先级`);
    if (requiresDvwa) reasons.push('当前任务扫描指纹确认 DVWA');
    reasons.push(...conditions);
    ranked.push({ playbook_id: playbook.playbook_id, name: playbook.name, difficulty: playbook.difficulty,
      baseline_group: playbook.baseline_group, match_score: Math.round(score * 10) / 10,
      match_reason: reasons.join('; '), match_stage: stage, match_stage_label: STAGE_LABEL[stage],
      match_status: status, match_status_label: STATUS_LABEL[status],
      match_conditions: [...conditions], match_evidence: sortedMatches.map(([kind, signal]) => ({
        kind, label: EVIDENCE_LABEL[kind], source_tool: signal.source_tool, scan_task_id: signal.scan_task_id,
        detail: signal.detail, strength: ['sqli', 'upload', 'xss', 'credential', 'vulnerability'].includes(kind) ? 'indication' : 'observation',
      })), automatic_eligible: status === 'ready' && stage === 'verification' });
  }
  const statusOrder = { ready: 0, needs_input: 1, already_checked: 2 };
  ranked.sort((first, second) => second.match_score - first.match_score
    || statusOrder[first.match_status] - statusOrder[second.match_status]
    || first.playbook_id.localeCompare(second.playbook_id));
  return ranked.slice(0, 10);
}

function collectEvidence(results) {
  const signals = new Map();
  for (const result of Array.isArray(results) ? results : []) {
    const data = readObject(result.result_data);
    const kind = findingKind(result, data);
    if (!kind) continue;
    const signal = { severity: SEVERITY_WEIGHT[result.severity] ?? 1,
      source_tool: result.source_tool || null, scan_task_id: result.scan_task_id || null,
      detail: String(data.finding || data.title || data.detail || data.template || result.result_type).slice(0, 300) };
    const existing = signals.get(kind);
    const signature = JSON.stringify(signal);
    if (!existing || signal.severity > existing.severity
      || signal.severity === existing.severity && signature < JSON.stringify(existing)) signals.set(kind, signal);
  }
  return signals;
}

function findingKind(result, data) {
  if (data.confirmed === false || data.vulnerable === false) return null;
  if (['http_probe', 'technology_detection'].includes(result.result_type)) {
    const status = Number(data.status_code);
    return data.url && (data.status_code === undefined || Number.isFinite(status) && status >= 200 && status < 400) ? 'web' : null;
  }
  if (['open_port', 'service_info'].includes(result.result_type)) return 'host';
  if (result.result_type === 'host_discovery') return data.status === 'up' ? 'host' : null;
  if (result.result_type === 'sql_injection') return 'sqli';
  if (['credential', 'weak_credential'].includes(result.result_type)) return 'credential';
  if (!['vulnerability', 'web_vuln', 'misconfiguration'].includes(result.result_type)) return null;
  if (['cloudmapper', 'pacu'].includes(result.source_tool)) return 'cloud';
  const text = [data.vuln_type, data.title, data.finding, data.detail, data.template, data.name, data.tags]
    .flat().filter(Boolean).join(' ').toLowerCase();
  if (!text || /not vulnerable|no (?:sql injection|vulnerabilities)|未发现.*(?:漏洞|注入)/.test(text)) return null;
  if (/httponly|secure flag/.test(text)) return 'cookies';
  if (/missing.*(?:header|hsts|csp)|x-frame-options|x-content-type-options|x-xss-protection|content-security-policy|安全.*头|响应头.*缺失/.test(text)) return 'headers';
  if (/sql[ _-]?(?:injection|inject|error)|sqli|error[ _-]?based[ _-]?sql|sql.*(?:syntax|注入)/.test(text)) return 'sqli';
  if (/file[ _-]?upload|arbitrary[ _-]?upload|文件上传/.test(text)) return 'upload';
  if (/\bxss\b|cross[ _-]?site[ _-]?scripting|跨站脚本/.test(text)) return 'xss';
  if (/default[ _-]?login|weak[ _-]?(?:password|credential)|弱口令|默认密码/.test(text)) return 'credential';
  if (/directory.*(?:index|listing)/.test(text)) return 'directory';
  if (/exposure|phpinfo|leak|\.git|sensitive information|信息泄露/.test(text)) return 'exposure';
  return 'vulnerability';
}

function describeAction(step) {
  const args = readArray(step.args_template);
  if (!args.length || args.some(argument => typeof argument !== 'string')) return null;
  const text = args.join(' ');
  const action = { key: step.tool_id, capabilities: {}, stage: 'reconnaissance',
    fixedEndpoint: args.some(argument => /^https?:\/\//.test(argument)) };
  switch (step.tool_id) {
    case 'nmap': return { ...action, key: 'nmap:ports', capabilities: { host: 2, web: 1 } };
    case 'httpx': case 'whatweb': return { ...action, key: `${step.tool_id}:fingerprint`, capabilities: { web: 2 } };
    case 'gobuster': case 'ffuf': case 'dirb':
      return { ...action, capabilities: { web: 1, directory: 2, exposure: 1 },
        fixedEndpoint: action.fixedEndpoint || /<target>:\d|<target>\/[^\s]*:\d/.test(text) };
    case 'arjun': return { ...action, capabilities: { web: 2 } };
    case 'nikto': return { ...action, key: 'nikto:web', stage: 'supplemental_scan',
      capabilities: { headers: 2, cookies: 2, exposure: 1, directory: 1, vulnerability: 1 } };
    case 'nuclei': {
      const selector = [argumentValue(args, '-id'), argumentValue(args, '-tags'), argumentValue(args, '-severity')].filter(Boolean).join(',');
      if (/sqli|fileupload|\bxss\b|default-login/.test(selector)) {
        const kinds = [['sqli', /sqli/], ['upload', /fileupload/], ['xss', /\bxss\b/], ['credential', /default-login/]]
          .filter(([, pattern]) => pattern.test(selector)).map(([kind]) => kind);
        return { ...action, key: `nuclei:${selector}`, stage: 'verification', requiredEvidence: kinds,
          capabilities: Object.fromEntries(kinds.map(kind => [kind, 2])) };
      }
      const capabilities = {};
      if (/http-missing-security-headers/.test(selector)) capabilities.headers = 2;
      if (/exposure|config|phpinfo/.test(selector)) Object.assign(capabilities, { exposure: /phpinfo/.test(selector) ? 2 : 1, directory: 1 });
      if (!selector) Object.assign(capabilities, { headers: 1, cookies: 1, exposure: 1, directory: 1, vulnerability: 1 });
      if (argumentValue(args, '-severity')) capabilities.vulnerability = 1;
      return { ...action, key: `nuclei:${selector || 'general'}`, stage: 'supplemental_scan', capabilities };
    }
    case 'sqlmap': return { ...action, stage: 'verification', requiredEvidence: ['sqli'],
      capabilities: { sqli: 2 }, needsSession: /--cookie.*(?:\{\{|<)/.test(text),
      needsReview: Number(argumentValue(args, '--risk') || 1) > 1 || Number(argumentValue(args, '--level') || 1) > 1,
      needsParameters: !/\{\{\s*sqli_url\s*\}\}|\?[^\s]+=/i.test(argumentValue(args, '-u') || '') && !argumentValue(args, '--data') };
    case 'hydra': case 'netexec':
      return { ...action, stage: 'verification', requiredEvidence: ['credential'], capabilities: { credential: 2 }, needsCredentials: true };
    case 'cloudmapper': case 'pacu': return { ...action, stage: 'supplemental_scan', capabilities: { cloud: 2 } };
    default: return null;
  }
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index >= 0) return args[index + 1] || '';
  return args.find(value => value.startsWith(name + '='))?.slice(name.length + 1) || '';
}

function hasParameterEntry(target) {
  try { return [...new URL(target).searchParams].some(([name, value]) => name && value); } catch { return false; }
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
