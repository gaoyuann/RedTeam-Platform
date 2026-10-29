import { pipelineScans } from './scanResultQuery.js';
import { summarizeScanRecords } from './scanResultCatalog.js';

export function topologyLinkedTasks(db, actor, {pipeline_id,scan_task_id,node_id}) {
  // Link metadata is server-authored at task creation and is immutable afterwards.
  const tasks=db.prepare(`SELECT * FROM pipelines WHERE json_valid(config)
    AND json_extract(config,'$.topology_source.node_id')=?
    AND json_extract(config,?)=? AND (?='admin' OR created_by=?) ORDER BY id DESC LIMIT 50`)
    .all(node_id,pipeline_id?'$.topology_source.pipeline_id':'$.topology_source.scan_task_id',
      pipeline_id || scan_task_id,actor.role,actor.sub);
  return tasks.map(task=>{
    const ids=pipelineScans(db,task).map(scan=>scan.scan_task_id);
    const records=ids.length ? db.prepare(`SELECT result_type,severity FROM scan_results WHERE scan_task_id IN (${ids.map(()=>'?').join(',')})`).all(...ids) : [];
    const counts=summarizeScanRecords(records);
    return {pipeline_id:task.pipeline_id,task_no:task.task_no,target:task.target,status:task.status,
      created_at:task.created_at,error_message:task.error_message ? '扫描存在错误，请打开任务查看详情' : null,
      finding_count:counts.categories.vulnerability};
  });
}
