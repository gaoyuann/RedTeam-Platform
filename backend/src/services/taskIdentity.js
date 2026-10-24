import { createHash, randomUUID } from 'node:crypto';

const fail = (status, message, code) => { throw Object.assign(new Error(message), { status, ...(code ? { code } : {}) }); };
export const isTaskNumber = value => typeof value === 'string' && /^TASK-\d{8}-\d{6,}$/i.test(value.trim());
export const isTaskIdentifier = value => isTaskNumber(value) || /^pipe_[a-z\d-]+$/i.test(value || '');
const dayFormatter = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit' });

// SQLite's historical datetime('now') values are UTC, as are ISO values ending in Z.
export function taskNumberDay(value) {
  if (typeof value !== 'string') throw new Error('任务创建时间无效，无法生成任务ID');
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/);
  if (!match) throw new Error('任务创建时间格式无效，无法生成任务ID');
  const [, year, month, day, hour, minute, second, fraction = '', zone = 'Z'] = match;
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));
  if (calendar.getUTCFullYear() !== Number(year) || calendar.getUTCMonth() + 1 !== Number(month)
      || calendar.getUTCDate() !== Number(day) || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59)
    throw new Error('任务创建时间无效，无法生成任务ID');
  const date = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}${fraction}${zone}`);
  if (!Number.isFinite(date.getTime())) throw new Error('任务创建时间无效，无法生成任务ID');
  const parts = Object.fromEntries(dayFormatter.formatToParts(date).map(part => [part.type, part.value]));
  return `${parts.year}${parts.month}${parts.day}`;
}

export function hasTaskIdentity(db) {
  return db.prepare('PRAGMA table_info(pipelines)').all().some(column => column.name === 'task_no');
}

// Every caller holds an immediate write transaction. Counters survive task deletion.
export function allocateTaskNumber(db, createdAt) {
  if (!db.inTransaction) throw new Error('任务发号必须在写事务中进行');
  const day = taskNumberDay(createdAt);
  db.prepare('INSERT OR IGNORE INTO task_number_counters(day,last_value) VALUES (?,0)').run(day);
  const current = db.prepare('SELECT last_value FROM task_number_counters WHERE day=?').get(day).last_value;
  if (!Number.isSafeInteger(current) || current >= Number.MAX_SAFE_INTEGER) fail(503, '任务ID序号已达上限');
  const next = current + 1;
  db.prepare('UPDATE task_number_counters SET last_value=? WHERE day=?').run(next, day);
  return `TASK-${day}-${String(next).padStart(6, '0')}`;
}

const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
export const creationHash = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export function validateCreationRequest(value) {
  if (value !== undefined && (typeof value !== 'string' || !/^[a-zA-Z\d_-]{8,128}$/.test(value))) fail(400, '创建请求编号无效');
}
export function existingCreation(db, owner, requestId, hash) {
  if (!requestId) return null;
  if (!hasTaskIdentity(db)) fail(503, '任务ID迁移尚未安装，请先更新后端数据库');
  const request = db.prepare('SELECT * FROM task_creation_requests WHERE owner=? AND request_id=?').get(owner, requestId);
  if (!request) return null;
  if (request.request_hash !== hash) fail(409, '同一创建请求编号的内容已变化，请重新创建');
  const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=? AND created_by=?').get(request.pipeline_id, owner);
  if (!row) fail(409, '原创建请求对应的任务已删除，不能重复创建');
  return row;
}

export function insertNumberedTask(db, { target, config, owner, ownerRole, now = new Date().toISOString(), requestId, hash, checkLimits }) {
  if (!hasTaskIdentity(db)) fail(503, '任务ID迁移尚未安装，请先更新后端数据库');
  return db.transaction(() => {
    // Async source validation may outlive the account state checked at the route entrance.
    // Hold the write lock before rechecking, including when returning an existing request.
    const account = db.prepare('SELECT role,is_active FROM users WHERE username=?').get(owner);
    if (account?.is_active !== 1 || ownerRole !== undefined && account.role !== ownerRole)
      fail(401, '登录身份已失效，请重新登录', 'AUTH_REQUIRED');
    const known = existingCreation(db, owner, requestId, hash);
    if (known) return { row: known, reused: true };
    const limit = checkLimits?.();
    if (limit) fail(429, limit);
    const taskNo = allocateTaskNumber(db, now);
    let pipelineId;
    for (let attempt = 0; attempt < 3; attempt++) {
      pipelineId = `pipe_${randomUUID()}`;
      try {
        db.prepare(`INSERT INTO pipelines(pipeline_id,task_no,target,status,config,created_by,created_at,updated_at)
          VALUES (?,?,?,'created',?,?,?,?)`).run(pipelineId, taskNo, target, JSON.stringify(config), owner, now, now);
        break;
      } catch (error) {
        if (!error.message.includes('UNIQUE constraint failed: pipelines.pipeline_id') || attempt === 2) throw error;
      }
    }
    if (requestId) db.prepare(`INSERT INTO task_creation_requests(owner,request_id,request_hash,pipeline_id,task_no)
      VALUES (?,?,?,?,?)`).run(owner, requestId, hash, pipelineId, taskNo);
    return { row: db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(pipelineId), reused: false };
  }).immediate();
}

export function visibleTaskLookup(db, actor, identifier) {
  const value = identifier.trim();
  const column = isTaskNumber(value) ? 'task_no' : 'pipeline_id';
  if (column === 'task_no' && !hasTaskIdentity(db)) fail(503, '任务ID迁移尚未安装');
  return db.prepare(`SELECT * FROM pipelines WHERE ${column}=? COLLATE NOCASE AND (?='admin' OR created_by=?)`)
    .get(value, actor.role, actor.sub) || null;
}
