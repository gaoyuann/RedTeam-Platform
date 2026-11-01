import { pipelineScans } from './scanResultQuery.js';

// A scan-agent audit row anchors ownership, but its child checks contain the
// actual evidence. Reuse task result scope checks instead of target equality.
export function planScanSources(db, target, identifiers, owner) {
  const ids = [...new Set((Array.isArray(identifiers) ? identifiers : [identifiers])
    .filter(id => typeof id === 'string' && id))];
  if (!ids.length) return [];
  const anchor = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(ids[0]);
  if (!anchor || owner !== undefined && anchor.created_by !== owner) return [];
  let allowed = null;
  if (anchor.pipeline_id) {
    const task = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(anchor.pipeline_id);
    if (task && task.created_by === anchor.created_by && task.target === target)
      allowed = new Set(pipelineScans(db, task).map(scan => scan.scan_task_id));
  }
  return db.prepare(`SELECT * FROM scan_tasks WHERE scan_task_id IN (${ids.map(() => '?').join(',')})
    AND created_by IS ? AND status IN ('COMPLETED','PARTIAL') ORDER BY id`).all(...ids, anchor.created_by)
    .filter(scan => allowed ? allowed.has(scan.scan_task_id) : scan.target === target
      && (!scan.pipeline_id || scan.pipeline_id === anchor.pipeline_id));
}

export const planObservationTypesExcluded = [
  'lan_scope', 'lan_host_discovery', 'network_context', 'network_link', 'raw_output',
  'scan_error', 'scan_warning', 'scan_evidence', 'scan_agent_step', 'scan_agent_summary',
  'scan_capability_assessment', 'web_agent_step', 'web_scan_summary',
];
