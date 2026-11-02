// Keep immutable evidence/report provenance while removing tasks from active navigation.
export function hasTaskDeletions(db) {
  return Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='task_deletions'").get());
}
export function visibleTasksSql(db, alias = 'pipelines') {
  return hasTaskDeletions(db)
    ? `NOT EXISTS (SELECT 1 FROM task_deletions d WHERE d.pipeline_id=${alias}.pipeline_id)` : '1=1';
}
export function isTaskDeleted(db, id) {
  return hasTaskDeletions(db) && Boolean(db.prepare('SELECT 1 FROM task_deletions WHERE pipeline_id=?').get(id));
}
export function isScanTaskDeleted(db, task) {
  if (!task || !hasTaskDeletions(db)) return false;
  // Older scans only appear in the parent's comma-separated scan_task_id field.
  return Boolean(db.prepare(`SELECT 1 FROM task_deletions d JOIN pipelines p ON p.pipeline_id=d.pipeline_id
    WHERE p.pipeline_id=? OR instr(',' || replace(coalesce(p.scan_task_id,''),' ','') || ',', ',' || ? || ',')>0 LIMIT 1`)
    .get(task.pipeline_id || '',task.scan_task_id));
}
const table = (db, name) => Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name));
export function deleteTask(db, pipeline, actor) {
  return db.transaction(() => {
    if (isTaskDeleted(db, pipeline.pipeline_id)) return;
    const id = pipeline.pipeline_id;
    const current = db.prepare('SELECT status,run_id,scan_task_id FROM pipelines WHERE pipeline_id=?').get(id);
    const fail = message => { throw Object.assign(new Error(message), {status:409}); };
    if (['running','awaiting_approval'].includes(current.status)) fail('任务尚未结束，请先取消任务');
    const hasLink = db.prepare('PRAGMA table_info(scan_tasks)').all().some(c => c.name === 'pipeline_id');
    const scanIds = new Set(String(current.scan_task_id || '').split(',').map(id=>id.trim()).filter(Boolean));
    if (hasLink) for (const s of db.prepare('SELECT scan_task_id FROM scan_tasks WHERE pipeline_id=?').all(id)) scanIds.add(s.scan_task_id);
    for (const scanId of scanIds) {
      if (db.prepare("SELECT 1 FROM scan_tasks WHERE scan_task_id=? AND status IN ('RUNNING','PENDING')").get(scanId)) fail('关联扫描尚未结束，请先取消任务');
      if (table(db,'scan_tool_runs') && db.prepare(`SELECT 1 FROM scan_tool_runs WHERE scan_task_id=?
        AND (state NOT IN ('completed','failed','timed_out','cancelled')
          OR CASE WHEN json_valid(outcome) THEN json_extract(outcome,'$.stopped') ELSE NULL END IS NOT 1)`)
        .get(scanId)) fail('工具停止未确认，请稍后重试');
    }
    if (current.run_id && db.prepare("SELECT 1 FROM execution_runs WHERE run_id=? AND status IN ('PENDING','CREATED','QUEUED','RUNNING','PAUSED','CANCELLING')").get(current.run_id)) fail('关联执行尚未结束，请先取消任务');
    if (table(db,'finding_verification_attempts') && db.prepare("SELECT 1 FROM finding_verification_attempts WHERE pipeline_id=? AND (state IN ('queued','running','cancelling','unknown') OR stop_confirmed=0)").get(id)) fail('漏洞验证停止未确认，请先停止验证');
    if (!hasTaskDeletions(db)) throw Object.assign(new Error('任务删除迁移尚未安装，请更新并重启后端'), {status:503});
    db.prepare('INSERT INTO task_deletions(pipeline_id,deleted_by) VALUES (?,?)').run(id,actor.sub);
  }).immediate();
}
