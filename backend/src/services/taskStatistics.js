import {attemptVerificationSummary} from './findingVerificationSummary.js';
import { scanCollection } from './scanResultQuery.js';
import { publicScanRecord, parseResultData as json, resultCategory, redactScanValue } from './scanResultCatalog.js';
import { hash, hasStatistics, scopedFindingIdentity, identityInScope, statisticsScope, fail } from './findingInstances.js';
import { isTargetInScope } from './taskScope.js';
const tally=rows=>rows.reduce((out,key)=>{out[key]=(out[key]||0)+1;return out;},{});
const exists=(db,name)=>!!db.prepare("SELECT 1 FROM sqlite_master WHERE name=?").get(name);
const terminal=['completed','failed','aborted'];
const severityOrder=['unknown','info','low','medium','high','critical'];
const ratio=(n,d,complete)=>({numerator:n,denominator:complete?d:null,value:complete&&d>0?n/d:null,reason:!complete?'基准未知或不完整':d===0?'不适用':null});
export function taskStatistics(db,pipeline) {
  return db.transaction(()=>{
    if(pipeline.run_id && !db.prepare('SELECT 1 FROM execution_runs WHERE run_id=? AND user_sub=? AND target=?').get(pipeline.run_id,pipeline.created_by,pipeline.target))fail(409,'任务主执行来源不匹配');
    const scope=statisticsScope(pipeline);
    const collection=scanCollection(db,pipeline), candidates=collection.rows.filter(r=>resultCategory(r)==='vulnerability');
    const candidateMap=new Map(candidates.map(r=>[r.id,r]));
    const enabled=hasStatistics(db);
    const maps=enabled?db.prepare(`SELECT m.*,i.identity,i.rule_version FROM finding_instance_records m
      JOIN finding_instances i ON i.instance_id=m.instance_id AND i.pipeline_id=m.pipeline_id WHERE m.pipeline_id=? ORDER BY m.finding_id`).all(pipeline.pipeline_id):[];
    const valid=maps.filter(m=>candidateMap.has(m.finding_id) && JSON.stringify(scopedFindingIdentity(candidateMap.get(m.finding_id),pipeline))===m.identity);
    const mapped=new Set(valid.map(m=>m.finding_id));
    const allAttempts=exists(db,'finding_verification_attempts')?db.prepare(`SELECT a.*,v.finding_id FROM finding_verification_attempts a
      JOIN finding_verifications v ON v.id=a.verification_id AND v.pipeline_id=a.pipeline_id
      WHERE a.pipeline_id=? ORDER BY a.rowid`).all(pipeline.pipeline_id):[];
    const attempts=allAttempts.filter(a=>candidateMap.has(a.finding_id));
    const runIds=new Set(pipeline.run_id?[pipeline.run_id]:[]), histories=new Map();
    const attemptViews=attempts.map(a=>{
      const run=db.prepare('SELECT * FROM execution_runs WHERE run_id=?').get(a.run_id);
      const linkage=json(run?.plan_data)?.finding_verification;
      const plan=db.prepare('SELECT content,fingerprint FROM finding_verification_plans WHERE verification_id=? AND revision=?').get(a.verification_id,a.revision);
      const sourceValid=run?.user_sub===pipeline.created_by && linkage?.pipeline_id===pipeline.pipeline_id
        && linkage?.finding_id===a.finding_id && linkage?.attempt_id===a.id && linkage?.verification_id===a.verification_id
        && linkage?.revision===a.revision && !!plan && linkage?.fingerprint===plan.fingerprint
        && json(plan.content)?.target===run.target && !!scope && isTargetInScope(scope,run.target);
      if(sourceValid)runIds.add(a.run_id);
      const evidence=sourceValid?db.prepare(`SELECT e.id,e.evidence_data,e.target,e.step_index,e.tool_id,e.attempt_id,
        x.run_id AS attempt_run,x.step_index AS attempt_step,x.tool_id AS attempt_tool
        FROM evidence_records e LEFT JOIN execution_attempts x ON x.id=e.attempt_id WHERE e.run_id=? ORDER BY e.id`).all(a.run_id):[];
      const eligible=evidence.filter(e=>e.attempt_run===a.run_id && e.attempt_step===e.step_index && e.attempt_tool===e.tool_id && e.target===run.target
        && json(e.evidence_data)?.finding_verification?.finding_id===a.finding_id
        && json(e.evidence_data)?.finding_verification?.pipeline_id===pipeline.pipeline_id
        && json(e.evidence_data)?.finding_verification?.attempt_id===a.id
        && json(e.evidence_data)?.finding_verification?.verification_id===a.verification_id
        && json(e.evidence_data)?.finding_verification?.revision===a.revision
        && json(e.evidence_data)?.finding_verification?.fingerprint===plan.fingerprint);
      const flags=eligible.map(e=>json(e.evidence_data)?.finding_verification?.tool_started);
      const stopped=a.stop_confirmed===1 && terminal.includes(a.state);
      const started=flags.includes(true)?true:stopped && flags.length && flags.every(f=>f===false)?false:
        stopped && sourceValid && (run.preflight_status==='FAILED' || json(run.final_summary)?.verification_dispatch_started===false)?false:null;
      const assessment=exists(db,'finding_verification_assessments')?db.prepare('SELECT * FROM finding_verification_assessments WHERE attempt_id=? ORDER BY id DESC LIMIT 1').get(a.id):null;
      const system=attemptVerificationSummary(db,{id:a.verification_id,finding_id:a.finding_id,state:a.state,revision:a.revision},a);
      const judgement=assessment, ids=system.result.evidence_ids;
      const evidenceValid=sourceValid && Array.isArray(ids) && ids.length>0 && ids.every(id=>eligible.some(e=>e.id===id));
      const conclusion=system.conclusion;
      const view={id:a.id,finding_id:a.finding_id,run_id:a.run_id,revision:a.revision,state:a.state,stop_confirmed:!!a.stop_confirmed,
        started,conclusion,method:system.method,result:system.result,human_opinions:system.human_opinions,evidence_ids:evidenceValid?ids:[],
        source_valid:!!sourceValid,plan:sourceValid?redactScanValue(json(plan.content)):null,
        judgement:judgement && evidenceValid?redactScanValue(judgement):null,created_at:a.created_at,completed_at:a.completed_at};
      if(!histories.has(a.finding_id))histories.set(a.finding_id,[]);histories.get(a.finding_id).push(view);
      return view;
    });
    const groups=new Map();
    for(const m of valid) {
      if(!groups.has(m.instance_id))groups.set(m.instance_id,{instance_id:m.instance_id,identity:JSON.parse(m.identity),rule_version:m.rule_version,record_ids:[]});
      groups.get(m.instance_id).record_ids.push(m.finding_id);
    }
    const instances=[...groups.values()].map(g=>{
      const latest=g.record_ids.map(id=>histories.get(id)?.at(-1)).filter(Boolean);
      const conclusions=new Set(latest.map(a=>a.conclusion));
      const definite=['confirmed','not_verified','false_positive'].filter(c=>conclusions.has(c));
      const conclusion=definite.length>1?'conflict':definite[0] || (conclusions.has('inconclusive')?'inconclusive':'pending');
      const all=g.record_ids.flatMap(id=>histories.get(id)||[]);
      const severity=severityOrder[g.record_ids.reduce((maximum,id)=>Math.max(maximum,severityOrder.indexOf(String(candidateMap.get(id).severity).toLowerCase())),0)];
      return {...g,severity,conclusion,executed:all.some(a=>a.started===true),historically_confirmed:all.some(a=>a.conclusion==='confirmed'),attempts:all};
    }).sort((a,b)=>a.instance_id.localeCompare(b.instance_id));
    const checks=exists(db,'task_checks')?db.prepare('SELECT * FROM task_checks WHERE pipeline_id=? ORDER BY check_id').all(pipeline.pipeline_id):null;
    const assets=exists(db,'task_assets')?db.prepare('SELECT * FROM task_assets WHERE pipeline_id=? ORDER BY asset_id').all(pipeline.pipeline_id):null;
    const services=exists(db,'task_services')?db.prepare('SELECT * FROM task_services WHERE pipeline_id=? ORDER BY service_id').all(pipeline.pipeline_id):[];
    const baseline=enabled?db.prepare(`SELECT b.* FROM task_baselines b JOIN task_baseline_selection s ON s.baseline_id=b.id AND s.pipeline_id=b.pipeline_id WHERE b.pipeline_id=?`).get(pipeline.pipeline_id):null;
    const content=baseline?JSON.parse(baseline.content):null;
    const baselineApplicable=!!content && !!scope && (!scope.environment_ref || scope.environment_ref===content.environment_id)
      && content.assets.every(a=>isTargetInScope(scope,a.target)) && content.vulnerabilities.every(v=>identityInScope(v.identity,scope));
    const baselineRatio=(n,d,complete)=>{
      if(content && !baselineApplicable)return {numerator:null,denominator:null,value:null,reason:'基准与当前任务环境或范围不匹配'};
      return ratio(n,d,complete);
    };
    const matched=(content?.vulnerabilities || []).map(v=>({id:v.id,instance_ids:instances.filter(i=>JSON.stringify(i.identity)===JSON.stringify(v.identity)).map(i=>i.instance_id)}));
    const security=new Set(['web_security','service_security','parameter_validation','form_input_validation','authenticated_roles','new_entry_check',
      'web_scan','vuln_scan','auth_audit','source_scan','program_scan','brute_force','ad_scan','cloud_scan']);
    const covered=(baselineApplicable?content.assets:[]).filter(a=>(checks||[]).some(c=>{
      if(c.state!=='completed' || !security.has(c.check_type))return false;
      const service=services.find(s=>s.service_id===c.service_id), asset=assets?.find(x=>x.asset_id===service?.asset_id);
      return !!(c.target || asset?.host) && isTargetInScope({includes:[a.target],excludes:[]},c.target || asset.host);
    })).map(a=>a.id);
    const ids=[...runIds].filter(id=>db.prepare('SELECT 1 FROM execution_runs WHERE run_id=? AND user_sub=?').get(id,pipeline.created_by));
    const executionRows=table=>ids.length?db.prepare(`SELECT * FROM ${table} WHERE run_id IN (${ids.map(()=>'?')}) ORDER BY id`).all(...ids):[];
    const steps=executionRows('execution_steps'), calls=executionRows('execution_attempts');
    const toolOutcomes=collection.runs.map(r=>json(r.outcome)||{});
    const linkedScans=[...new Set(String(pipeline.scan_task_id || '').split(',').map(s=>s.trim()).filter(Boolean))];
    const lifecycleScans=db.prepare(`SELECT scan_task_id,pipeline_id,created_by,status FROM scan_tasks WHERE pipeline_id=?
      OR scan_task_id IN (${linkedScans.map(()=>'?').join(',') || "''"}) ORDER BY scan_task_id`).all(pipeline.pipeline_id,...linkedScans);
    const lifecycleIds=lifecycleScans.map(s=>s.scan_task_id);
    const lifecycleRuns=lifecycleIds.length?db.prepare(`SELECT tool_run_id,scan_task_id,state,completed_at,outcome FROM scan_tool_runs
      WHERE scan_task_id IN (${lifecycleIds.map(()=>'?').join(',')}) ORDER BY tool_run_id`).all(...lifecycleIds):[];
    const verificationRuns=allAttempts.map(a=>db.prepare('SELECT run_id,user_sub,status FROM execution_runs WHERE run_id=?').get(a.run_id) || null);
    const ready=verificationRuns.every(r=>r?.user_sub===pipeline.created_by && ['COMPLETED','FAILED','ABORTED'].includes(r.status))
      && linkedScans.every(id=>lifecycleIds.includes(id)) && !(checks || []).some(c=>c.state==='running') && attemptViews.every(a=>a.source_valid) && ['completed','failed','cancelled'].includes(pipeline.status)
      && lifecycleScans.every(s=>s.created_by===pipeline.created_by && (!s.pipeline_id || s.pipeline_id===pipeline.pipeline_id) && ['COMPLETED','PARTIAL','FAILED','CANCELLED'].includes(s.status))
      && lifecycleRuns.every(r=>r.state!=='running' && !!r.completed_at && json(r.outcome)?.stopped===true)
      && allAttempts.every(a=>terminal.includes(a.state)&&a.stop_confirmed===1)
      && (!pipeline.run_id || !!db.prepare("SELECT 1 FROM execution_runs WHERE run_id=? AND status IN ('COMPLETED','FAILED','ABORTED')").get(pipeline.run_id));
    const statistics={schema_version:1,result_schema_version:1,result_policy:'system_evidence_only',assets:{observed:assets?.length??null,states:assets?tally(assets.map(a=>a.state)):null,covered_baseline:covered.length,coverage:baselineRatio(covered.length,content?.assets.length||0,!!content?.assets_complete),covered_ids:covered},
      checks:{total:checks?.length??null,states:checks?tally(checks.map(c=>c.state)):null,reason:'检查项与工具调用分别统计',tool_outcomes:{total:toolOutcomes.length,states:tally(collection.runs.map(r=>r.state)),reason_unknown:toolOutcomes.filter(o=>typeof o.timed_out!=='boolean'||typeof o.aborted!=='boolean').length,timed_out:toolOutcomes.filter(o=>o.timed_out===true).length,aborted:toolOutcomes.filter(o=>o.aborted===true).length}},
      findings:{records:candidates.length,instances:instances.length,mapped_records:mapped.size,unmapped_records:candidates.length-mapped.size,
        complete:enabled&&mapped.size===candidates.length,sync_pending:candidates.some(r=>!mapped.has(r.id)&&scopedFindingIdentity(r,pipeline)!==null),severity:tally(instances.map(i=>i.severity))},
      verifications:{result_schema_version:1,system_results:tally(attemptViews.map(a=>a.result.status)),human_opinions:attemptViews.reduce((n,a)=>n+a.human_opinions.length,0),executed_instances:instances.filter(i=>i.executed).length,confirmed_instances:instances.filter(i=>i.conclusion==='confirmed').length,
        conclusions:tally(instances.map(i=>i.conclusion)),attempts:attemptViews.length,started:attemptViews.filter(a=>a.started===true).length,
        not_started:attemptViews.filter(a=>a.started===false).length,start_unknown:attemptViews.filter(a=>a.started===null).length,
        unmapped_attempts:attemptViews.filter(a=>!mapped.has(a.finding_id)).length},
      execution:{steps:steps.length,tool_calls:calls.length},baseline:content?{applicable:baselineApplicable,id:baseline.id,content_hash:baseline.content_hash,environment_id:content.environment_id,environment_version:content.environment_version,
        known_assets:content.assets.length,known_vulnerabilities:content.vulnerabilities.length,matches:matched,
        discovery:baselineRatio(matched.filter(m=>m.instance_ids.length).length,matched.length,content.vulnerabilities_complete),
        confirmed:matched.filter(m=>m.instance_ids.some(id=>instances.some(i=>i.instance_id===id&&i.conclusion==='confirmed'))).length}:null,
      completeness:{migration_available:enabled,scope_available:!!scope,scope_reason:scope?null:'历史目标缺少可解析的授权范围，保留记录且不自动归并',unmapped_reason:mapped.size<candidates.length?'候选未同步或缺少可靠归并身份':null},report_ready:ready};
    const source_fingerprint=hash({result_schema_version:1,result_policy:'system_evidence_only',pipeline,lifecycleScans,lifecycleRuns,verificationRuns,scans:collection.scans,records:collection.rows,runs:collection.runs,maps,allAttempts,attempts:attemptViews,checks,assets,services,baseline,steps,calls,evidence:executionRows('evidence_records'),
      verification_sources:exists(db,'finding_verifications')?db.prepare('SELECT * FROM finding_verifications WHERE pipeline_id=? ORDER BY id').all(pipeline.pipeline_id):[],
      plan_history:db.prepare('SELECT * FROM task_plan_history WHERE pipeline_id=? ORDER BY id').all(pipeline.pipeline_id),
      run_sources:ids.map(id=>db.prepare('SELECT * FROM execution_runs WHERE run_id=?').get(id)),
      plans:db.prepare('SELECT * FROM task_plans WHERE pipeline_id=?').all(pipeline.pipeline_id),
      main_playbook:pipeline.run_id?db.prepare('SELECT p.* FROM playbooks p JOIN execution_runs r ON p.playbook_id=r.playbook_id WHERE r.run_id=?').get(pipeline.run_id):null,
      main_steps:pipeline.run_id?db.prepare('SELECT p.* FROM playbook_steps p JOIN execution_runs r ON p.playbook_id=r.playbook_id WHERE r.run_id=? ORDER BY p.step_index').all(pipeline.run_id):[]});
    statistics.source_fingerprint=source_fingerprint;
    return {statistics,instances:instances.map(redactScanValue),checks:checks?.map(redactScanValue)||[],baseline:content,
      records:candidates.map(publicScanRecord),attempts:attemptViews,source_fingerprint};
  })();
}
