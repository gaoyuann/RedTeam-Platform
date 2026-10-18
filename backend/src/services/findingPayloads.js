import { createHash } from 'node:crypto';
import { getPayloadIndex } from './payloadLoader.js';
import { parseResultData, resultCategory } from './scanResultCatalog.js';
import { findingSignature } from './findingPayload.js';

const KINDS = [
  ['nosqli', /\bno.?sql\s*injection\b|NoSQL\s*注入/i],
  ['sqli', /\b(?:sql\s*injection|sqli|sqlmap)\b|SQL\s*注入/i],
  ['xss', /\b(?:xss|cross.site scripting)\b|跨站脚本/i],
  ['ssrf', /\b(?:ssrf|server.side request forgery)\b|服务端请求伪造/i],
  ['csrf', /\bcsrf\b|跨站请求伪造/i],
  ['rce', /\b(?:remote code execution|command injection|rce)\b|远程代码执行|命令注入/i],
  ['lfi', /\b(?:lfi|local file inclusion)\b|本地文件包含/i],
  ['xxe', /\bxxe\b|XML\s*外部实体/i],
  ['upload', /\b(?:file upload|unrestricted upload)\b|文件上传漏洞/i],
];
const PRODUCT_GROUPS = [
  ['mysql', /\bmysql\b/i], ['mssql', /\b(?:mssql|sql\s*server)\b/i],
  ['postgres', /\b(?:postgres(?:ql)?)\b/i], ['sqlite', /\bsqlite\b/i],
  ['oracle', /\boracle\b/i], ['mongodb', /\bmongodb\b/i],
  ['redis', /\bredis\b/i], ['log4j', /\b(?:log4j|log4shell)\b/i],
  ['fastjson', /\bfastjson\b/i], ['struts2', /\bstruts\s*2\b/i],
  ['weblogic', /\bweblogic\b/i], ['thinkphp', /\bthinkphp\b/i],
  ['laravel', /\blaravel\b/i],
];
const VARIANTS = [
  ['blind', /\b(?:blind|boolean.based)\b|盲注/i], ['time', /\btime.based\b|时间盲注/i],
  ['error', /\berror.based\b|报错注入/i], ['union', /\bunion\b|联合查询注入/i],
  ['second-order', /\bsecond.order\b|二次注入/i], ['stacked', /\bstacked\b|堆叠注入/i],
  ['reflected', /\breflected\b|反射型/i], ['stored', /\bstored\b|存储型/i],
  ['dom', /\bdom\b|DOM\s*型/i], ['bypass', /\bbypass\b|绕过/i],
  ['advanced', /\badvanced\b|高级利用/i], ['encoding', /\bencoding\b|编码绕过/i],
  ['polyglot', /\bpolyglot\b/i], ['beef', /\bbeef\b/i],
  ['mxss', /\bmxss\b|变异型\s*XSS/i], ['unicode', /\bunicode\b/i],
  ['cookie-theft', /\bcookie.theft\b|窃取\s*Cookie/i], ['keylogger', /\bkeylogger\b/i],
  ['command-injection', /\bcommand.injection\b|命令注入/i],
  ['deserialize', /\b(?:deserializ(?:e|ation)|unserializ(?:e|ation))\b|反序列化/i],
  ['file-upload', /\bfile.upload\b|文件上传/i],
  ['include', /\b(?:file.inclusion|include)\b|文件包含/i],
  ['log-poison', /\blog.poison(?:ing)?\b|日志投毒/i],
  ['htaccess', /\bhtaccess\b/i], ['image', /\bimage\b|图片/i],
  ['php-filter', /\bphp.filter\b/i], ['php', /\bphp\b/i], ['java', /\bjava\b/i],
  ['cloud', /\b(?:cloud|metadata|imds)\b|云环境|元数据/i],
  ['aws', /\baws\b/i], ['gcp', /\bgcp\b/i], ['azure', /\bazure\b/i],
  ['protocol', /\bprotocol\b|协议/i], ['gopher', /\bgopher\b/i],
  ['dict', /\bdict\b/i], ['file', /\bfile\b|文件读取/i],
  ['dns-rebinding', /\bdns.rebinding\b|DNS\s*重绑定/i],
  ['redis', /\bredis\b/i], ['mysql', /\bmysql\b/i], ['mongodb', /\bmongodb\b/i],
];
const negated = /\b(?:not vulnerable|no vulnerability|false positive|not affected)\b|未发现漏洞|不存在漏洞|误报/i;
const safeText = value => typeof value === 'string' ? value : '';
const metadataText = value => Array.isArray(value) ? value.map(safeText).join(' ') : safeText(value);
const nameOf = value => typeof value === 'string' ? value : value?.zh || value?.en || '';
const identifiers = text => new Set((text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(v => v.toUpperCase()));

function findingSignals(row) {
  if (resultCategory(row) !== 'vulnerability') return null;
  const data = parseResultData(row.result_data) || {};
  const fields = typeof data === 'object' ? [data.title, data.name, data.finding, data.vulnerability,
    data.template, data.cve, data.cwe, data.description, data.reason, data.legacy_text,
    data.detail, data.technique, data.dbms, data.info?.name, data.info?.description,
    data.info?.classification?.['cve-id'], data.info?.classification?.['cwe-id']] : [data];
  const text = fields.map(metadataText).join(' ').replace(/\bhttps?:\/\/[^\s]+/gi, '');
  if (negated.test(text)) return null;
  const kind = row.result_type === 'sql_injection' ? 'sqli'
    : KINDS.find(([, pattern]) => pattern.test(text))?.[0];
  const cves = identifiers(text);
  if (!kind && !cves.size) return null;
  return { kind, cves, text, products: PRODUCT_GROUPS.filter(([, pattern]) => pattern.test(text)).map(([key]) => key) };
}

function payloadDescriptor(payload) {
  const tags = Array.isArray(payload.tags) ? payload.tags.map(safeText) : [];
  const primary = [payload.id, ...tags, nameOf(payload.name)].join(' ');
  const searchable = [primary, nameOf(payload.category)].join(' ');
  const kind = tags.some(tag => /^nosql$/i.test(tag)) ? 'nosqli'
    : KINDS.find(([, pattern]) => pattern.test(primary))?.[0]
      || KINDS.find(([, pattern]) => pattern.test(nameOf(payload.category)))?.[0];
  const products = PRODUCT_GROUPS.filter(([, pattern]) => pattern.test(searchable)).map(([key]) => key);
  const variants = VARIANTS.filter(([, pattern]) => pattern.test(payload.id || '')).map(([key]) => key);
  const references = Array.isArray(payload.references) ? payload.references.map(ref => typeof ref === 'string' ? ref : ref?.url || '').join(' ') : '';
  return { kind, products, variants, cves: identifiers([payload.id, ...tags, references].join(' ')) };
}

export function payloadVersion(payload) {
  const { _source, ...content } = payload;
  return 'sha256:' + createHash('sha256').update(JSON.stringify(content)).digest('hex');
}

export function matchPayloads(db, row, index = getPayloadIndex(db)) {
  const signal = findingSignals(row);
  const signature = findingSignature(db, row);
  if (!signal && !signature) return [];
  const matches = [];
  for (const payload of Object.values(index)) {
    if (!payload?.id) continue;
    const descriptor = payloadDescriptor(payload);
    const signatureMatch = !!signature && payload.applicability?.signature === signature;
    if (payload.applicability?.signature && !signatureMatch) continue;
    const exactCve = signal && [...signal.cves].find(cve => descriptor.cves.has(cve));
    if (!signal && !signatureMatch) continue;
    if (!signatureMatch && !exactCve && (!signal.kind || signal.kind !== descriptor.kind)) continue;
    const productOverlap = !!signal && descriptor.products.some(product => signal.products.includes(product));
    const classPrefix = !!signal && (payload.id.toLowerCase().startsWith(`${signal.kind}-`)
      || signal.kind === 'nosqli' && payload.id.toLowerCase().startsWith('sqli-'));
    const productPrefix = !!signal && descriptor.products.some(product => signal.products.includes(product)
      && payload.id.toLowerCase().startsWith(`${product}-`));
    // Legacy tool commands and combined techniques are references, not a specific finding's payload.
    if (!signatureMatch && !exactCve && (payload._type === 'tool' || payload._type !== 'ai_generated'
      && !classPrefix && !productPrefix)) continue;
    if (!signatureMatch && !exactCve && descriptor.variants.some(variant =>
      !VARIANTS.find(([key]) => key === variant)?.[1].test(signal.text))) continue;
    if (!signatureMatch && descriptor.products.length && signal.products.length && !productOverlap) continue;
    const missing = [];
    if (!signatureMatch && descriptor.products.length && !signal.products.length)
      missing.push(`确认目标产品属于 ${descriptor.products.join(' / ')}`);
    if (!signatureMatch && exactCve && descriptor.variants.length && !descriptor.variants.every(variant =>
      VARIANTS.find(([key]) => key === variant)?.[1].test(signal.text)))
      missing.push(`确认 ${descriptor.variants.join(' / ')} 变体适用`);
    const prerequisites = Array.isArray(payload.prerequisites) ? payload.prerequisites.map(nameOf).filter(Boolean) : [];
    if (prerequisites.length) missing.push('逐项核对载荷前置条件');
    const payloadType = payload._payload_type || payload._type || 'unknown';
    const basis = signatureMatch ? '漏洞上下文签名与生成时一致'
      : exactCve ? `漏洞标识 ${exactCve} 与载荷元数据一致`
      : `发现类型 ${signal.kind} 与载荷分类/标签一致；尚需核对具体入口`;
    matches.push({
      payload_id: payload.id, name: nameOf(payload.name) || payload.id,
      version: payloadVersion(payload), payload_type: payloadType,
      consumption: payload.consumption?.type === 'tool_args' ? 'tool_args'
        : payloadType === 'tool' ? 'tool_command_reference' : 'playbook_step_reference',
      availability: 'available', match_status: (signatureMatch || exactCve) && !missing.length ? 'specific_candidate' : 'needs_review',
      match_basis: basis, prerequisites, missing_conditions: missing,
      variables: payload.variables && typeof payload.variables === 'object' ? payload.variables : {},
      source: payload._source || 'static',
      score: signatureMatch ? 110 : exactCve ? 100 : 20 + (productOverlap ? 6 : 0)
        + descriptor.variants.length * 3 + (/\b(?:basic|reflected)\b/i.test(payload.id) ? 2 : 0) - missing.length,
    });
  }
  matches.sort((a, b) => b.score - a.score || a.payload_id.localeCompare(b.payload_id));
  return matches.map(({ score, ...match }) => match);
}

function linkRows(db, findingId) {
  try {
    return db.prepare('SELECT * FROM finding_payload_links WHERE scan_result_id=? ORDER BY active DESC,id DESC').all(findingId);
  } catch (error) {
    if (error.message.includes('no such table')) return [];
    throw error;
  }
}

export function findingPayloadMatches(db, row, index = getPayloadIndex(db)) {
  const matches = matchPayloads(db, row, index);
  const links = linkRows(db, row.id).map(link => {
    const payload = index[link.payload_id];
    return {
      payload_id: link.payload_id, version: link.payload_version, active: Boolean(link.active),
      current_version: payload ? payloadVersion(payload) : null,
      availability: !payload ? 'unavailable' : payloadVersion(payload) === link.payload_version ? 'available' : 'changed',
      match_basis: link.match_basis, consumption: link.consumption,
      created_by: link.created_by, created_at: link.created_at,
    };
  });
  return { finding_id: row.id, matches: matches.map(match => ({ ...match,
    linked: links.some(link => link.active && link.payload_id === match.payload_id && link.version === match.version) })), links };
}

export function findingPayloadSummary(db, row, index = getPayloadIndex(db)) {
  if (resultCategory(row) !== 'vulnerability') return null;
  const { matches, links } = findingPayloadMatches(db, row, index);
  const active = links.find(link => link.active);
  const current = active && matches.find(match => match.payload_id === active.payload_id && match.version === active.version);
  if (active) return { status: active.availability === 'available' && current ? 'linked' : 'stale',
    payload_id: active.payload_id, name: current?.name || active.payload_id,
    version: active.version, match_basis: active.match_basis };
  const first = matches[0];
  return first ? { status: 'candidate', payload_id: first.payload_id, name: first.name,
    version: first.version, match_basis: first.match_basis } : { status: 'none', payload_id: null, name: null };
}

export function bindFindingPayload(db, row, payloadId, version, actor) {
  if (resultCategory(row) !== 'vulnerability') throw Object.assign(new Error('只能关联漏洞发现'), { status: 400 });
  if (typeof payloadId !== 'string' || !payloadId || typeof version !== 'string' || !version)
    throw Object.assign(new Error('payload_id 和 version 必填'), { status: 400 });
  const write = db.transaction(() => {
    const index = getPayloadIndex(db);
    const payload = index[payloadId];
    if (!payload) throw Object.assign(new Error('载荷不存在或尚未审核通过'), { status: 404 });
    if (payloadVersion(payload) !== version) throw Object.assign(new Error('载荷版本已变化，请刷新匹配结果'), { status: 409 });
    const candidate = matchPayloads(db, row, index).find(match => match.payload_id === payloadId);
    if (!candidate) throw Object.assign(new Error('该载荷与当前漏洞没有可解释的匹配依据'), { status: 400 });
    db.prepare('UPDATE finding_payload_links SET active=0 WHERE scan_result_id=? AND payload_id=? AND active=1 AND payload_version<>?')
      .run(row.id, payloadId, version);
    db.prepare(`INSERT INTO finding_payload_links(scan_result_id,payload_id,payload_version,match_basis,consumption,created_by)
      VALUES(?,?,?,?,?,?) ON CONFLICT(scan_result_id,payload_id,payload_version) DO UPDATE SET active=1`)
      .run(row.id, payloadId, version, candidate.match_basis, candidate.consumption, actor);
    return findingPayloadMatches(db, row, index);
  });
  return write();
}
