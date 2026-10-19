export function playbookScope(db, playbook, visited = new Set()) {
  if (!playbook || visited.has(playbook.playbook_id) || visited.size >= 16)
    return { private: true, owner: null, snapshot: false };
  visited.add(playbook.playbook_id);
  const approved = db.prepare(`SELECT pipeline.created_by FROM task_plans AS plan
    JOIN pipelines AS pipeline ON pipeline.pipeline_id = plan.pipeline_id
    WHERE plan.approved_playbook_id = ?`).get(playbook.playbook_id);
  if (approved) return { private: true, owner: approved.created_by || null, snapshot: true };
  let metadata;
  try { metadata = JSON.parse(playbook.metadata || '{}'); } catch {}
  if (metadata?.finding_verification) {
    const owner = db.prepare('SELECT created_by FROM pipelines WHERE pipeline_id=?').get(metadata.finding_verification.pipeline_id);
    return {private:true, owner:owner?.created_by || null, snapshot:true};
  }
  if (metadata && Object.hasOwn(metadata, 'task_plan')) {
    const pipelineId = metadata.task_plan?.pipeline_id;
    const pipeline = typeof pipelineId === 'string'
      ? db.prepare('SELECT created_by FROM pipelines WHERE pipeline_id = ?').get(pipelineId) : null;
    return { private: true, owner: pipeline?.created_by || null, snapshot: true };
  }
  if (!playbook.is_generated || playbook.generated_from === 'imported')
    return { private: false, owner: null, snapshot: false };
  const source = typeof playbook.generated_from === 'string' ? playbook.generated_from : '';
  const scan = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(source);
  if (scan) return { private: true, owner: scan.created_by || null, snapshot: false };
  const parent = db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(source);
  const scope = parent ? playbookScope(db, parent, visited) : null;
  return { private: true, owner: scope?.private ? scope.owner : null, snapshot: scope?.snapshot || false };
}

export function canReadPlaybook(db, playbook, actor) {
  if (!playbook || !actor?.sub || !['admin', 'user'].includes(actor.role)) return false;
  const scope = playbookScope(db, playbook);
  return actor.role === 'admin' || !scope.private || scope.owner === actor.sub;
}

export function assertPlaybookUse(db, playbookId, actor, owner = actor?.sub) {
  const playbook = typeof playbookId === 'string'
    ? db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(playbookId) : null;
  if (!playbook) throw Object.assign(new Error('预案不存在'), { status: 404 });
  const scope = playbookScope(db, playbook);
  if (!canReadPlaybook(db, playbook, actor) || scope.private && (!scope.owner || scope.owner !== owner))
    throw Object.assign(new Error('预案不属于当前操作的任务所有者'), { status: 403 });
  if (scope.snapshot)
    throw Object.assign(new Error('批准预案为只读任务快照，请从所属任务的执行入口操作'), { status: 409 });
  return playbook;
}
