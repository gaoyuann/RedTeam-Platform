// Source-assisted playbooks carry code excerpts and must retain scan ownership.
export function canAccessProgramPlaybook(db,user,playbook) {
  let source;
  try {source=JSON.parse(playbook?.metadata || '{}').source_verification;} catch {}
  if(!source) return true;
  if(user?.role==='admin') return true;
  const task=db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id=?').get(source.scan_task_id);
  return !!task && !!user?.sub && task.created_by===user.sub;
}
export function canAccessProgramRun(db,user,run) {
  if (!canAccessProgramTask(db,user,run?.scan_task_id)) return false;
  const playbook=run?.playbook_id && db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(run.playbook_id);
  return canAccessProgramPlaybook(db,user,playbook);
}

export function canAccessProgramTask(db, user, scanTaskId) {
  if (!scanTaskId) return true;
  const task = db.prepare('SELECT scan_type,created_by FROM scan_tasks WHERE scan_task_id=?').get(scanTaskId);
  return !task || task.scan_type !== 'source_scan' || user?.role === 'admin' || !!user?.sub && task.created_by === user.sub;
}
export function canAccessProgramReport(db, user, report) {
  if (!canAccessProgramTask(db, user, report?.scan_task_id)) return false;
  const run = report?.run_id && db.prepare('SELECT playbook_id,scan_task_id FROM execution_runs WHERE run_id=?').get(report.run_id);
  return canAccessProgramRun(db, user, run);
}
