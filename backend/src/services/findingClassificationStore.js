import { createHash } from 'node:crypto';
import { publicScanRecord, resultCategory, redactScanValue } from './scanResultCatalog.js';

export const SCENARIO_CATEGORIES = Object.freeze({
  'data-exfiltration': '数据抵近窃取',
  'tampering-deception': '信息篡改欺骗',
  'device-control': '关键设备夺控',
  'cross-network-disruption': '跨网致瘫',
  'wireless-attack': '无线攻击',
});
export const CLASSIFICATION_VERSION = 1;
const MAX_EVIDENCE_CHARS = 6000;
export const hasFindingClassifications = db => !!db.prepare(
  "SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_classifications'"
).get();

export function classificationInput(row, scan) {
  const publicRow = publicScanRecord(row);
  const evidence = publicRow.result_data;
  const context = { finding_id: row.id, result_type: row.result_type, severity: row.severity,
    source_tool: row.source_tool, scan_type: scan?.scan_type || null,
    scan_target: redactScanValue(scan?.target || ''), evidence };
  const input_hash = createHash('sha256').update(JSON.stringify({ version: CLASSIFICATION_VERSION, ...context })).digest('hex');
  return { input_hash, input: { ...context, evidence: evidence.slice(0, MAX_EVIDENCE_CHARS),
    evidence_truncated: evidence.length > MAX_EVIDENCE_CHARS } };
}

// Reading old databases must not require a migration or call a model.
export function findingClassification(db, pipelineId, row, scan) {
  if (resultCategory(row) !== 'vulnerability') return null;
  if (!hasFindingClassifications(db)) return { schema_version: 1, state: 'unavailable', categories: [] };
  const saved = db.prepare('SELECT * FROM finding_classifications WHERE pipeline_id=? AND finding_id=?').get(pipelineId, row.id);
  if (!saved) return { schema_version: 1, state: 'unclassified', categories: [] };
  let result;
  try { result = JSON.parse(saved.result); } catch { result = null; }
  const valid = result && result.schema_version === CLASSIFICATION_VERSION && Array.isArray(result.categories)
    && result.categories.every(category => Object.hasOwn(SCENARIO_CATEGORIES, category))
    && typeof result.reason === 'string' && ['high', 'medium', 'low'].includes(result.confidence)
    && Array.isArray(result.missing_conditions) && result.missing_conditions.every(item => typeof item === 'string');
  if (!valid) return { schema_version: 1, state: 'stale', categories: [], reason: '历史分类格式无效，请重新分类' };
  const stale = saved.input_hash !== classificationInput(row, scan).input_hash;
  return { ...result, state: stale ? 'stale' : result.categories.length ? 'classified' : 'unknown',
    updated_at: saved.updated_at, input_hash: saved.input_hash };
}
