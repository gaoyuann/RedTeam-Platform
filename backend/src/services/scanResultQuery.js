import { verificationSummary } from './findingVerificationSummary.js';
import { normalizeTopologyTarget } from './nmapTopology.js';
import { hasScanIntegrity } from './scanResultStore.js';
import { parseResultData, publicScanRecord, summarizeScanRecords, redactScanValue, resultCategory } from './scanResultCatalog.js';
import { isProgramMode, programExecutionTarget, programNetworkTarget } from './programScan.js';
import { isTargetInScope, taskScope } from './taskScope.js';
import { scanCoverage } from './scanCoverage.js';
import { getPayloadIndex } from './payloadLoader.js';
import { findingPayloadSummary } from './findingPayloads.js';

export function pipelineScans(db,pipeline) {
  const linked=[...new Set(String(pipeline.scan_task_id || '').split(',').map(s=>s.trim()).filter(Boolean))];
  const modern=hasScanIntegrity(db);
  const rows=db.prepare(`SELECT * FROM scan_tasks WHERE created_by IS ? AND (${modern?'pipeline_id=? OR ':''}scan_task_id IN (${linked.map(()=>'?').join(',') || "''"})) ORDER BY id`)
    .all(pipeline.created_by,...(modern?[pipeline.pipeline_id]:[]),...linked);
  const config=parseResultData(pipeline.config) || {};
  const targets=new Set([pipeline.target]);
  if(isProgramMode(config.scan_mode) || String(pipeline.target).startsWith('tcp://')) {
    try {targets.add(programNetworkTarget(programExecutionTarget(pipeline) || pipeline.target));} catch {}
  }
  return rows.filter(row=>{
    if(row.pipeline_id && row.pipeline_id!==pipeline.pipeline_id) return false;
    if(row.pipeline_id===pipeline.pipeline_id && config.task_scope) {
      const value=/^[^/]+:\d+$/.test(row.target) ? `tcp://${row.target}` : row.target;
      return isTargetInScope(taskScope(pipeline),value);
    }
    if(targets.has(row.target)) return true;
    if(row.scan_type==='topology_scan') { try {return row.target===normalizeTopologyTarget(pipeline.target);}catch{} }
    return false;
  });
}
export function scanCollection(db,pipeline,{metadataOnly=false}={}) {
  const scans=pipelineScans(db,pipeline), ids=scans.map(s=>s.scan_task_id);
  const rows=ids.length?db.prepare(`SELECT ${metadataOnly?"id,scan_task_id,result_type,severity,source_tool,captured_at,CASE WHEN source_tool='nikto' AND result_type IN ('web_vuln','information') THEN result_data ELSE NULL END AS result_data":'*' } FROM scan_results WHERE scan_task_id IN (${ids.map(()=>'?').join(',')}) ORDER BY id`).all(...ids):[];
  const runs=ids.length && hasScanIntegrity(db)?db.prepare(`SELECT ${metadataOnly?'tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,completed_at,outcome,diagnostics':'*'} FROM scan_tool_runs WHERE scan_task_id IN (${ids.map(()=>'?').join(',')}) ORDER BY started_at,tool_run_id`).all(...ids):[];
  const states={}; for(const s of scans) states[s.status]=(states[s.status] || 0)+1;
  const step=db.prepare("SELECT input_data,output_data FROM pipeline_steps WHERE pipeline_id=? AND step_type='scan' ORDER BY step_order LIMIT 1").get(pipeline.pipeline_id);
  const input=parseResultData(step?.input_data);
  const planned=Array.isArray(input?.scan_types)?input.scan_types:[];
  const missing=planned.filter(type=>!scans.some(s=>s.scan_type===type));
  const legacy=scans.some(s=>!runs.some(r=>r.scan_task_id===s.scan_task_id));
  const parserUnknown=runs.some(r=>parseResultData(r.outcome)?.parser_coverage_known===false);
  const activeCalls=runs.filter(r=>r.state==='running' || parseResultData(r.outcome)?.stopped===false).map(r=>r.tool_run_id);
  const coverage=scanCoverage(db,pipeline.pipeline_id);
  const unfinishedStates=['planned','running','partial','failed','cancelled','unreachable','unsupported','missing_condition','not_checked'];
  const summary={...summarizeScanRecords(rows),scan_count:scans.length,states,
    completeness: !scans.length?'unknown':scans.every(s=>s.status==='COMPLETED') && !missing.length && !activeCalls.length && runs.every(r=>!parseResultData(r.outcome)?.incomplete)?(legacy || parserUnknown?'unknown':'complete'):'incomplete',
    planned_checks:planned,unexecuted_checks:missing,
    coverage_states:coverage?.states || null,
    unfinished_check_count:coverage ? unfinishedStates.reduce((total,state)=>total+(coverage.states[state] || 0),0) : null,
    legacy_completeness_unknown:legacy,
    active_calls:activeCalls};
  return {scans,rows,runs,summary,coverage};
}
export function scanPage(db,pipeline,query={}) {
  const integer=(v,fallback,max)=>{
    if(v===undefined) return fallback;
    if(!/^\d+$/.test(String(v)) || !Number.isSafeInteger(Number(v)) || Number(v)>max) throw Object.assign(new Error('分页参数无效'),{status:400});
    return Number(v);
  };
  const limit=integer(query.limit,100,500); if(!limit) throw Object.assign(new Error('limit 必须大于零'),{status:400});
  const after=integer(query.after,0,Number.MAX_SAFE_INTEGER);
  const collection=scanCollection(db,pipeline,{metadataOnly:true});
  const through=integer(query.through,collection.rows.at(-1)?.id || 0,Number.MAX_SAFE_INTEGER);
  collection.rows=collection.rows.filter(r=>r.id<=through);
  collection.summary={...collection.summary,...summarizeScanRecords(collection.rows)};
  const category=query.category || 'all';
  if(category!=='all' && !Object.hasOwn(collection.summary.categories,category)) throw Object.assign(new Error('结果分类无效'),{status:400});
  if(query.scan_task_id && !collection.scans.some(s=>s.scan_task_id===query.scan_task_id)) throw Object.assign(new Error('子扫描不属于此任务'),{status:404});
  const publicRows=collection.rows.map(row=>({...row,category:resultCategory(row)}));
  const filtered=publicRows.filter(r=>(category==='all'||r.category===category) && (!query.scan_task_id||r.scan_task_id===query.scan_task_id));
  const selected=filtered.filter(r=>r.id>after).slice(0,limit);
  const payloadIndex = selected.some(row=>row.category==='vulnerability') ? getPayloadIndex(db) : null;
  const records=selected.length?db.prepare(`SELECT * FROM scan_results WHERE id IN (${selected.map(()=>'?').join(',')}) ORDER BY id`).all(...selected.map(r=>r.id))
    .map(row=>({...publicScanRecord(row),verification:verificationSummary(db,row.id,pipeline.pipeline_id),payload_match:payloadIndex ? findingPayloadSummary(db,row,payloadIndex) : null})):[];
  const processIds=collection.rows.filter(r=>['web_agent_step','web_scan_summary','scan_agent_step','scan_agent_summary','scan_capability_assessment'].includes(r.result_type) && (!query.scan_task_id || r.scan_task_id===query.scan_task_id)).map(r=>r.id);
  const process=processIds.length?db.prepare(`SELECT * FROM scan_results WHERE id IN (${processIds.slice(-100).map(()=>'?')}) ORDER BY id`).all(...processIds.slice(-100)).map(publicScanRecord):[];
  return {web_scan_process:process,web_scan_process_truncated:processIds.length>100,scan_summary:collection.summary,scan_coverage:collection.coverage,scan_records:records,
    scan_sources:collection.scans.map(s=>({scan_task_id:s.scan_task_id,scan_type:s.scan_type,status:s.status,target:s.target,error_message:redactScanValue(s.error_message),retry_of_scan_task_id:s.retry_of_scan_task_id || null})),
    scan_runs:collection.runs.map(({evidence,...r})=>({...r,outcome:parseResultData(r.outcome),diagnostics:parseResultData(r.diagnostics)})),
    page:{total:filtered.length,returned:selected.length,after,through,limit,category,scan_task_id:query.scan_task_id || null,
      has_more:filtered.some(r=>r.id>(selected.at(-1)?.id ?? after)),next_after:selected.at(-1)?.id ?? after}};
}
