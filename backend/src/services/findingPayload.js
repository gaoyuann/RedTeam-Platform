import { createHash } from 'node:crypto';
import { publicScanRecord, resultCategory } from './scanResultCatalog.js';
import { getPayloadIndex } from './payloadLoader.js';

const CONTEXT_FIELDS = ['title', 'name', 'finding', 'detail', 'template', 'cve', 'cve_id', 'vuln_type', 'parameter', 'path', 'url', 'matched_at', 'product', 'version', 'cwe', 'preconditions'];

export function findingPayloadCategory(context) {
  const text = [context.result_type, context.details.title, context.details.finding,
    context.details.vuln_type, context.details.template].filter(Boolean).join(' ');
  if (/sql.?injection|sqli|sql.?注入/i.test(text)) return 'SQL/NoSQL注入';
  if (/xss|cross.site.scripting|跨站脚本/i.test(text)) return 'XSS跨站脚本';
  if (/ssrf|服务端请求伪造/i.test(text)) return 'SSRF服务端请求伪造';
  if (/\blfi\b|file inclusion|文件包含/i.test(text)) return 'LFI/RFI文件包含';
  if (/\brce\b|command injection|远程代码执行|命令注入/i.test(text)) return 'RCE远程代码执行';
  return String(context.details.vuln_type || context.details.title || context.details.finding || context.result_type).slice(0, 120);
}

function contextFromRow(row) {
  if (resultCategory(row) !== 'vulnerability') throw Object.assign(new Error('该记录不是可验证的漏洞发现'), { status: 400 });
  const safe = publicScanRecord(row);
  const data = JSON.parse(safe.result_data || '{}');
  const details = Object.fromEntries(CONTEXT_FIELDS.filter(key => data[key] != null)
    .map(key => [key, String(data[key]).slice(0, 500)]));
  if (/\b(?:not vulnerable|no vulnerability|false positive|not affected)\b|未发现漏洞|不存在漏洞|误报/i
    .test([details.title, details.finding, details.detail].filter(Boolean).join(' ')))
    throw Object.assign(new Error('该记录不支持生成攻击载荷：发现内容表明漏洞未成立'), { status: 422 });
  const identity = details.cve || details.cve_id || details.template || details.vuln_type || details.title || details.finding;
  if (!identity) throw Object.assign(new Error('漏洞缺少可复用的类型或标识，无法生成载荷'), { status: 422 });
  const targetType = /^(?:https?|tcp):\/\//i.test(row.target || '') || ['web_vuln','sql_injection'].includes(row.result_type) ? 'web' : 'intranet';
  let location = details.path || '';
  try { location ||= new URL(details.matched_at || details.url).pathname; } catch { /* non-URL finding */ }
  const signature = createHash('sha256').update(JSON.stringify([
    row.result_type, String(identity).trim().toLowerCase(), details.product?.toLowerCase() || '',
    details.version?.toLowerCase() || '', location.toLowerCase(),
    (details.parameter || '').toLowerCase(), targetType,
  ])).digest('hex');
  return { finding_id: row.id, scan_task_id: row.scan_task_id, result_type: row.result_type,
    severity: row.severity, source_tool: row.source_tool, target_type: targetType,
    target: String(row.target || '').slice(0, 500), details, signature };
}

export function findingSignature(db, row) {
  try {
    const target = row.target || db.prepare('SELECT target FROM scan_tasks WHERE scan_task_id=?').get(row.scan_task_id)?.target;
    return contextFromRow({ ...row, target }).signature;
  } catch { return null; }
}

export function loadFindingContext(db, findingId, actor) {
  if (!Number.isSafeInteger(findingId) || findingId < 1) throw Object.assign(new Error('finding_id 必须是正整数'), { status: 400 });
  const row = db.prepare(`SELECT r.*, t.target, t.created_by, t.scan_type
    FROM scan_results r JOIN scan_tasks t ON t.scan_task_id = r.scan_task_id WHERE r.id = ?`).get(findingId);
  if (!row) throw Object.assign(new Error('漏洞记录不存在'), { status: 404 });
  if (actor.role !== 'admin' && row.created_by !== actor.sub) throw Object.assign(new Error('无权查看此漏洞记录'), { status: 403 });
  return contextFromRow(row);
}

export function findReusablePayload(db, context) {
  // Only structured, validated payloads can be automatically reused. Legacy
  // static samples are still available in the library as references.
  for (const payload of Object.values(getPayloadIndex(db))) {
    if (payload?.applicability?.signature === context.signature && payload?.consumption?.type === 'tool_args') {
      return { payload, match_reason: '相同漏洞标识、产品版本和目标类型' };
    }
  }
  return null;
}
