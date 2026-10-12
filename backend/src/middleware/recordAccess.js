const resources = {
  scan: { table: 'scan_tasks', id: 'scan_task_id', owner: 'created_by' },
  run: { table: 'execution_runs', id: 'run_id', owner: 'user_sub' },
  report: { table: 'test_reports', id: 'report_id', owner: 'generated_by' },
  capture: { table: 'capture_tasks', id: 'capture_task_id', owner: 'created_by' },
  campaign: { table: 'campaigns', id: 'campaign_id', owner: 'created_by' },
  pipeline: { table: 'pipelines', id: 'pipeline_id', owner: 'created_by' },
};

export function currentActor(db, user) {
  if (!user || typeof user.sub !== 'string' || !user.sub.trim() || !['admin', 'user'].includes(user.role)) return null;
  try {
    const actor = db.prepare('SELECT username, role, is_active FROM users WHERE username = ?').get(user.sub);
    return actor?.is_active === 1 && actor.role === user.role ? actor : null;
  } catch {
    return null;
  }
}

export function requireActor(db) {
  return (req, res, next) => {
    if (!currentActor(db, req.user))
      return res.status(401).json({ status: 'error', error: { message: '登录身份已失效，请重新登录', code: 'AUTH_REQUIRED' } });
    next();
  };
}

export function getRecord(db, kind, identifier) {
  const resource = resources[kind];
  if (!resource || typeof identifier !== 'string' || !identifier) return null;
  return db.prepare(`SELECT * FROM ${resource.table} WHERE ${resource.id} = ?`).get(identifier) || null;
}

export function recordOwner(kind, record) {
  return record?.[resources[kind]?.owner] || null;
}

export function canAccessRecord(db, kind, record, user) {
  if (!record || !user?.sub || !['admin', 'user'].includes(user.role)) return false;
  if (user.role === 'admin') return true;
  if (kind !== 'report') return recordOwner(kind, record) === user.sub;
  const sources = [];
  if (record.run_id) sources.push(['run', record.run_id]);
  if (record.scan_task_id) sources.push(['scan', record.scan_task_id]);
  if (!sources.length) return record.generated_by === user.sub;
  return sources.every(([sourceKind, identifier]) => canAccessRecord(db, sourceKind, getRecord(db, sourceKind, identifier), user));
}

export function checkRecordAccess(db, kind, identifier, req, res) {
  const record = getRecord(db, kind, identifier);
  if (!record) {
    res.status(404).json({ status: 'error', error: { message: '记录不存在' } });
    return false;
  }
  if (!canAccessRecord(db, kind, record, req.user)) {
    res.status(403).json({ status: 'error', error: { message: '没有权限访问此记录', code: 'FORBIDDEN' } });
    return false;
  }
  return true;
}

export function recordParam(db, kind) {
  return (req, res, next, identifier) => {
    if (checkRecordAccess(db, kind, identifier, req, res)) next();
  };
}
