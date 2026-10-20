import { isIP } from 'node:net';
import {cscanSourcePath} from './cscanTarget.js';

function invalid(message) { throw Object.assign(new Error(message), { status: 400 }); }

function address(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 256) invalid('测试范围地址无效');
  const raw = value.trim();
  if(raw.startsWith('/src/')) return {kind:'source',value:cscanSourcePath(raw),path:cscanSourcePath(raw)};
  if (/^https?:\/\//i.test(raw) || /^tcp:\/\//i.test(raw)) {
    let url;
    try { url = new URL(raw); } catch { invalid('测试范围 URL 无效'); }
    if (!['http:', 'https:', 'tcp:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.hash)
      invalid('测试范围 URL 不允许凭据、片段或其他协议');
    if (/%(?:2f|5c|2e|00|0a|0d)/i.test(url.pathname) || url.pathname.includes('\\'))
      invalid('测试范围 URL 路径包含可能绕过边界的编码');
    if (url.protocol === 'tcp:' && (!url.port || !['', '/'].includes(url.pathname) || url.search)) invalid('TCP 范围必须包含主机和端口');
    return { kind: url.protocol === 'tcp:' ? 'tcp' : 'url', value: url.href,
      host: url.hostname.replace(/^\[|\]$/g,'').toLowerCase(), port: url.port || (url.protocol === 'https:' ? '443' : '80'),
      protocol: url.protocol, path: url.pathname };
  }
  const cidr = raw.match(/^(.+)\/(\d{1,2})$/);
  if (cidr) {
    if (isIP(cidr[1]) !== 4 || Number(cidr[2]) > 32) invalid('仅支持 IPv4 CIDR 测试范围');
    return { kind: 'cidr', value: raw, host: cidr[1], bits: Number(cidr[2]) };
  }
  if (isIP(raw)) return { kind: 'host', value: raw, host: raw.toLowerCase() };
  if (!/^(?=.{1,253}$)[a-z\d](?:[a-z\d.-]*[a-z\d])?$/i.test(raw) || /^[\d.]+$/.test(raw)
      || raw.split('.').some(label => label.length > 63 || !/^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label)))
    invalid('测试范围主机名无效');
  return { kind: 'host', value: raw.toLowerCase(), host: raw.toLowerCase() };
}

function ipv4Number(ip) { return ip.split('.').reduce((n, part) => ((n << 8) | Number(part)) >>> 0, 0); }
function contains(rule, candidate) {
  if(rule.kind==='source' || candidate.kind==='source') return rule.kind===candidate.kind
    && (candidate.path===rule.path || candidate.path.startsWith(rule.path+'/'));
  if (rule.kind === 'cidr') {
    if (isIP(candidate.host) !== 4) return false;
    const mask = rule.bits === 0 ? 0 : (0xffffffff << (32 - rule.bits)) >>> 0;
    if (candidate.kind === 'cidr') return candidate.bits >= rule.bits
      && (ipv4Number(candidate.host) & mask) === (ipv4Number(rule.host) & mask);
    return (ipv4Number(candidate.host) & mask) === (ipv4Number(rule.host) & mask);
  }
  if (rule.kind === 'host') return candidate.kind !== 'cidr' && rule.host === candidate.host;
  if (rule.kind !== candidate.kind || rule.protocol !== candidate.protocol || rule.host !== candidate.host || rule.port !== candidate.port)
    return false;
  if (rule.kind === 'tcp') return true;
  const prefix = rule.path.endsWith('/') ? rule.path : `${rule.path}/`;
  return candidate.path === rule.path || candidate.path.startsWith(prefix);
}

export function normalizeTaskScope(config, target) {
  const raw = config?.task_scope;
  if (raw !== undefined && (typeof raw !== 'object' || raw === null || Array.isArray(raw))) invalid('测试范围配置无效');
  const scope = raw || {};
  const list = (value, fallback, label) => {
    if (value === undefined) return fallback;
    if (!Array.isArray(value) || value.length > 64 || value.some(item => typeof item !== 'string')) invalid(`${label}须为最多 64 个地址`);
    return [...new Set(value.map(item => address(item).value))];
  };
  const includes = list(scope.includes, [...new Set([address(target).value,...(config?.source_path?[cscanSourcePath(config.source_path)]:[])])], '测试范围');
  const excludes = list(scope.excludes, [], '排除项');
  if (!includes.length || !includes.some(rule => contains(address(rule), address(target)))) invalid('主目标必须包含在测试范围内');
  if (excludes.some(rule => contains(address(rule), address(target)))) invalid('主目标不能被排除');
  if(config?.source_path && (!includes.some(rule=>contains(address(rule),address(config.source_path)))
    || excludes.some(rule=>contains(address(rule),address(config.source_path))))) invalid('CScan 源码路径未包含在授权范围内或命中排除项');
  const location = scope.execution_location ?? 'scanner';
  if (!['scanner', 'remote'].includes(location)) invalid('扫描位置无效');
  for (const key of ['environment_ref', 'auth_config_ref']) {
    if (scope[key] != null && (typeof scope[key] !== 'string' || scope[key].length > 128 || /[\r\n]/.test(scope[key]))) invalid(`${key} 无效`);
  }
  const budget = scope.discovery_budget ?? 0;
  if (!Number.isSafeInteger(budget) || budget < 0 || budget > 100) invalid('新入口检查预算须为 0 至 100');
  return { version: 1, includes, excludes, execution_location: location,
    environment_ref: scope.environment_ref?.trim() || null, auth_config_ref: scope.auth_config_ref?.trim() || null,
    discovery_budget: budget };
}

export function scopeConditions(scope) {
  const missing = [];
  if (scope.execution_location === 'remote') missing.push('远端扫描位置尚未配置和联调');
  if (scope.auth_config_ref) missing.push('认证配置引用尚未连接可用的凭据提供方');
  return missing;
}

export function scopeBlockingConditions(scope) {
  return scope.execution_location === 'remote' ? ['远端扫描位置尚未配置和联调'] : [];
}

export function isTargetInScope(scope, candidate) {
  let parsed;
  try { parsed = address(candidate); } catch { return false; }
  return scope.includes.some(rule => contains(address(rule), parsed))
    && !scope.excludes.some(rule => contains(address(rule), parsed));
}

// A single IPv4 test may discover its directly connected LAN for topology only.
// Keep this scope separate from the task's service/security execution scope.
export function topologyDiscoveryScope(scope, target, cidr) {
  const network = address(cidr), requested = address(target);
  if (network.kind !== 'cidr') return null;
  const singleIPv4 = requested.kind !== 'cidr' && isIP(requested.host) === 4
    && contains(network, requested);
  if (scope && !isTargetInScope(scope, cidr)
      && !(singleIPv4 && isTargetInScope(scope, target))) return null;
  // Host discovery cannot honor URL paths or ports: exclude the whole host.
  const excludes = (scope?.excludes || []).map(address)
    .filter(rule => rule.kind !== 'source')
    .map(rule => rule.kind === 'cidr' ? rule.value : rule.host);
  return { includes: [network.value], excludes: [...new Set(excludes)] };
}

export function scopeBlockReason(scope, candidate, scanType = '') {
  if (!isTargetInScope(scope, candidate)) return '目标超出任务范围或命中排除项';
  const requested=address(candidate);
  if(requested.kind==='source' && scanType!=='source_scan') return '源码路径仅可提交 CScan 源码审计，不能用于网络扫描';
  if(requested.kind==='source' && scope.excludes.some(value=>contains(requested,address(value))))
    return '源码目录包含排除路径，当前 CScan 任务无法保证跳过这些文件；请缩小源码目标';
  const broadScan=['web_scan','vuln_scan','api_fuzz','auth_audit','program_scan','source_scan'].includes(scanType);
  if(broadScan && scanType!=='source_scan' && requested.kind==='url' && !scope.includes.some(value=>{
    const rule=address(value);
    return contains(rule,requested) && (rule.kind==='host' || rule.kind==='cidr' || rule.kind==='url' && rule.path==='/');
  })) return '当前扫描器无法保证不越过授权 URL 路径，请使用受控入口探测或扩大明确授权范围';
  if (broadScan && scope.excludes.some(value => {
    const excluded=address(value);
    return requested.kind==='url' && excluded.kind==='url' && contains(requested,excluded);
  })) return '当前扫描器无法保证跳过排除的 URL 路径，请缩小扫描入口或调整检查计划';
  if (requested.kind==='cidr' && scope.excludes.some(value => contains(requested,address(value))))
    return '网段包含排除目标，当前扫描器无法逐地址跳过';
  return null;
}

export function taskScope(pipeline) {
  let config = pipeline?.config;
  try { if (typeof config === 'string') config = JSON.parse(config); } catch { config = {}; }
  return normalizeTaskScope(config || {}, pipeline.target);
}
