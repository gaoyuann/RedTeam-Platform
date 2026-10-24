import { taskDisplayText } from './taskExecution.js';

const categories = ['risk_assessment', 'tech_stack', 'attack_surface', 'recommended_strategy'];

function objectValue(raw) {
  try {
    const value = JSON.parse(raw || '{}');
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}

function entryCount(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length ? 1 : 0;
  return typeof value === 'string' && value.length ? 1 : 0;
}

export function taskAnalysisIndex(db, actor, query) {
  const search = query.search === undefined ? '' : query.search;
  const state = query.state === undefined ? 'all' : query.state;
  const limitRaw = query.limit === undefined ? '50' : query.limit;
  const offsetRaw = query.offset === undefined ? '0' : query.offset;
  if (typeof search !== 'string' || search.length > 120 ||
      typeof state !== 'string' || !['all', 'available', 'pending'].includes(state) ||
      typeof limitRaw !== 'string' || !/^\d+$/.test(limitRaw) ||
      typeof offsetRaw !== 'string' || !/^\d+$/.test(offsetRaw) ||
      !Number.isSafeInteger(Number(offsetRaw)) ||
      Number(limitRaw) < 1 || Number(limitRaw) > 100) {
    const error = new Error('分析索引筛选参数无效');
    error.status = 400;
    throw error;
  }
  const limit = Number(limitRaw);
  const offset = Number(offsetRaw);
  const rows = db.prepare(`SELECT p.*,
      p.updated_at, p.config, p.analysis_result, s.status AS analysis_status, s.output_data
    FROM pipelines p LEFT JOIN pipeline_steps s ON s.id = (
      SELECT MAX(id) FROM pipeline_steps WHERE pipeline_id = p.pipeline_id AND step_type = 'analyze'
    ) WHERE (? = 'admin' OR p.created_by = ?) ORDER BY p.updated_at DESC, p.pipeline_id ASC`)
    .all(actor.role, actor.username);
  const needle = search.trim().toLowerCase();
  const records = [];
  for (const row of rows) {
    const config = objectValue(row.config);
    const taskName = taskDisplayText(typeof config.task_name === 'string' ? config.task_name : row.pipeline_id);
    const target = taskDisplayText(row.target);
    if (needle && ![row.task_no, row.pipeline_id, taskName, target, row.created_by]
      .some(value => String(value || '').toLowerCase().includes(needle))) continue;
    const analysis = objectValue(row.analysis_result);
    const counts = Object.fromEntries(categories.map(category => [category, entryCount(analysis[category])]));
    const totalEntries = Object.values(counts).reduce((total, count) => total + count, 0);
    const available = totalEntries > 0;
    if ((state === 'available' && !available) || (state === 'pending' && available)) continue;
    const output = objectValue(row.output_data);
    const source = !available ? 'none' : output.fallback === true ? 'fallback'
      : row.analysis_status === 'completed' && Object.keys(output).length ? 'structured' : 'unknown';
    records.push({
      pipeline_id: row.pipeline_id, task_no: row.task_no || null, task_name: taskName, target,
      owner: row.created_by || '', status: row.status, updated_at: row.updated_at,
      analysis: { available, source, step_status: row.analysis_status || 'not_recorded', counts, total_entries: totalEntries },
    });
  }
  return {
    schema_version: 1, records: records.slice(offset, offset + limit),
    total: records.length, limit, offset, search, state,
    notice: '仅索引当前账号可见任务的已存储候选条目，不是已验证漏洞计数；不执行模型或跨任务风险关联。',
  };
}
