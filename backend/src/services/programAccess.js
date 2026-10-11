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
  const playbook=run?.playbook_id && db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(run.playbook_id);
  return canAccessProgramPlaybook(db,user,playbook);
}
