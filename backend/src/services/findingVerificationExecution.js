import {createHash} from 'node:crypto';
import {attemptVerificationSummary} from './findingVerificationSummary.js';
import {pipelineScans} from './scanResultQuery.js';
import {taskScope,isTargetInScope} from './taskScope.js';
import {redactScanValue} from './scanResultCatalog.js';
import {findingClassification} from './findingClassificationStore.js';
const parse=v=>{try{return typeof v==='string'?JSON.parse(v):v;}catch{return null;}};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const has=(db,t)=>!!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
const safeText=v=>typeof v==='string'?redactScanValue(v).slice(0,2000):'';

// Separate child executions from the parent run. No writes, raw responses or credentials.
export function findingVerificationExecution(db,pipeline,{limit=100,summaryOnly=false}={}) {
  const output={schema_version:1,total:0,returned:0,has_more:false,active:0,completed:0,failed:0,aborted:0,unknown:0,invalid_source_count:0,items:[]};
  if(!has(db,'finding_verification_attempts'))return output;
  const scanIds=new Set(pipelineScans(db,pipeline).map(s=>s.scan_task_id));
  const rows=db.prepare(`SELECT a.*,v.finding_id,v.scan_task_id,p.content,p.fingerprint,r.target,r.user_sub,r.plan_data,
    f.scan_task_id AS finding_scan,f.result_data
    FROM finding_verification_attempts a JOIN finding_verifications v ON v.id=a.verification_id
    LEFT JOIN finding_verification_plans p ON p.verification_id=a.verification_id AND p.revision=a.revision
    LEFT JOIN execution_runs r ON r.run_id=a.run_id LEFT JOIN scan_results f ON f.id=v.finding_id
    WHERE a.pipeline_id=? AND v.pipeline_id=a.pipeline_id ORDER BY a.rowid DESC`).all(pipeline.pipeline_id);
  const valid=rows.filter(row=>{
    const plan=parse(row.content),link=parse(row.plan_data)?.finding_verification;
    let scoped=false;try{scoped=isTargetInScope(taskScope(pipeline),row.target);}catch{}
    const ok=plan && typeof plan==='object' && !Array.isArray(plan) && hash(plan)===row.fingerprint
      && row.user_sub===pipeline.created_by && row.target===plan.target && scoped
      && scanIds.has(row.finding_scan) && row.finding_scan===row.scan_task_id
      && link?.pipeline_id===pipeline.pipeline_id && link?.verification_id===row.verification_id
      && link?.attempt_id===row.id && link?.finding_id===row.finding_id
      && link?.revision===row.revision && link?.fingerprint===row.fingerprint;
    if(!ok)output.invalid_source_count++;
    return ok;
  });
  output.total=valid.length;
  for(const row of valid){if(['queued','running','cancelling'].includes(row.state))output.active++;else if(Object.hasOwn(output,row.state)&&typeof output[row.state]==='number')output[row.state]++;}
  if(summaryOnly)return output;
  const selected=valid.slice(0,Math.max(1,Math.min(200,Number.isSafeInteger(limit)?limit:100)));
  const classifications=new Map();
  output.items=selected.map(row=>{
    const item={id:row.verification_id,pipeline_id:row.pipeline_id,finding_id:row.finding_id,state:row.state,revision:row.revision};
    const summary=attemptVerificationSummary(db,item,row),plan=parse(row.content),finding=parse(row.result_data);
    if(!classifications.has(row.finding_id)) {
      const findingRow=db.prepare('SELECT * FROM scan_results WHERE id=?').get(row.finding_id);
      const scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(row.scan_task_id);
      classifications.set(row.finding_id,findingRow ? findingClassification(db,pipeline.pipeline_id,findingRow,scan) : null);
    }
    const classification=classifications.get(row.finding_id);
    return {attempt_id:row.id,verification_id:row.verification_id,finding_id:row.finding_id,run_id:row.run_id,revision:row.revision,
      classification,
      state:row.state,stop_confirmed:!!row.stop_confirmed,created_at:row.created_at,completed_at:row.completed_at,
      finding_name:safeText(finding?.title || finding?.finding || finding?.name) || `发现 #${row.finding_id}`,
      plan_name:safeText(plan.name),objective:summary.result.objective,result:summary.result,
      tool_calls:db.prepare('SELECT count(*) n FROM execution_attempts WHERE run_id=?').get(row.run_id).n,
      evidence_count:db.prepare('SELECT count(*) n FROM evidence_records WHERE run_id=?').get(row.run_id).n};
  });
  output.returned=output.items.length;output.has_more=valid.length>selected.length;
  return redactScanValue(output);
}
