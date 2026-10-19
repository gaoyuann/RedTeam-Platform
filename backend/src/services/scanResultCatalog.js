// Only an unqualified enumeration of these ordinary methods is informational.
// Additional methods or claims about unsafe behavior remain candidates for review.
export function ordinaryHttpMethods(row) {
  if(row.source_tool!=='nikto' || !['web_vuln','information'].includes(row.result_type))return false;
  const data=parseResultData(row.result_data);
  const finding=data?.finding ?? data?.legacy_text;
  if(typeof finding!=='string')return false;
  const match=finding.trim().match(/^Allowed HTTP Methods:\s*([A-Z]+(?:[\s,]+[A-Z]+)*)[.\s]*$/i);
  if(!match)return false;
  return match[1].split(/[\s,]+/).every(method=>['GET','POST','HEAD','OPTIONS'].includes(method.toUpperCase()));
}
// Raw records are not deduplicated vulnerability instances.
const vulnerabilities = new Set(['vulnerability','web_vuln','sql_injection','misconfiguration','auth_finding','source_vuln','source_finding','program_finding']);
const assets = new Set(['open_port','service_info','host_discovery','lan_host_discovery','network_context','network_link','lan_scope','http_probe','technology_detection','api_parameter','api_endpoint']);
export function resultCategory(row) {
  if (['scan_error','scan_warning'].includes(row.result_type)) return 'error';
  if (['raw_output','scan_evidence'].includes(row.result_type)) return 'evidence';
  if (row.result_type === 'credential') return 'credential';
  if (ordinaryHttpMethods(row)) return 'information';
  if (assets.has(row.result_type)) return 'asset';
  if (vulnerabilities.has(row.result_type)) return ['info','inf'].includes(String(row.severity || '').trim().toLowerCase()) ? 'information' : 'vulnerability';
  if (row.result_type === 'information') return 'information';
  return 'other';
}
export function summarizeScanRecords(rows) {
  const categories = {vulnerability:0,asset:0,information:0,credential:0,error:0,evidence:0,other:0};
  for (const row of rows) categories[resultCategory(row)]++;
  return { record_count: rows.length, categories, deduplicated: false, vulnerability_instance_count: null,
    tool_reported_count: null, count_basis: 'records' };
}
export function parseResultData(value) {
  if (typeof value !== 'string') return value ?? null;
  try { return JSON.parse(value); } catch { return { legacy_text: value }; }
}
// No length truncation here: callers must disclose evidence limits separately.
export function redactScanValue(value, key = '') {
  if (/password|passwd|secret|token|cookie|authorization|api.?key|credential|private.?key/i.test(key)) return '[已隐藏]';
  if (Array.isArray(value)) return value.map(item => redactScanValue(item));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,redactScanValue(v,k)]));
  if (typeof value !== 'string') return value;
  return value.replace(/^(?:cookie|set-cookie|authorization):[^\r\n]*/gim,'[认证或会话头已隐藏]')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g,'[私钥已隐藏]')
    .replace(/\b(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi,'$1[已隐藏]@')
    .replace(/\bBearer\s+[a-z0-9._~+/=-]+/gi,'Bearer [已隐藏]')
    .replace(/((?:password|passwd|secret|token|cookie|authorization|api[_-]?key)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,'$1[已隐藏]');
}
export function publicScanRecord(row) {
  const data = row.result_type === 'credential' ? { notice: '凭据内容已隐藏' } : redactScanValue(parseResultData(row.result_data));
  return {...row, category:resultCategory(row), result_data:JSON.stringify(data)};
}
