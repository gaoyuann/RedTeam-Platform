import {buildVerificationContract,normalizeVerificationObjectiveDraft} from './findingVerificationResult.js';
import { verificationObservation } from './findingVerificationEvidence.js';
import { findingSources,findingTemplate,planFingerprint,sourceMetadata } from './findingVerificationSources.js';
import { findingRule,directoryEvidenceCriteria } from './findingVerificationRules.js';
import { verificationPayloadCatalog,validateBoundPayload } from './findingVerificationPayloads.js';
import { findingVerificationEntry } from './findingVerificationEntry.js';
import { verificationSummary,attemptVerificationSummary } from './findingVerificationSummary.js';
import { randomUUID, createHash } from 'node:crypto';
import { pipelineScans } from './scanResultQuery.js';
import { publicScanRecord, resultCategory } from './scanResultCatalog.js';
import { taskDisplayValue } from './taskExecution.js';
import { taskScope, isTargetInScope, scopeConditions } from './taskScope.js';
import { validateExecutionScope } from './executionScope.js';
import { assertPlaybookUse } from './playbookAccess.js';
import { getPayloadById } from './payloadLoader.js';
import { findingPayloadMatches } from './findingPayloads.js';
import { compilePlaybook } from './playbookCompiler.js';
import {payloadArtifactView} from './findingPayloadArtifacts.js';

export const json = (value, fallback = {}) => { try { return typeof value === 'string' ? JSON.parse(value) : value ?? fallback; } catch { return fallback; } };
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const fingerprint = content => createHash('sha256').update(JSON.stringify(content)).digest('hex');
const text = (value, label, max = 4000) => {
  if (typeof value !== 'string' || !value.trim() || value.length > max) fail(400, `${label}不能为空且不能超长`);
  return value.trim();
};
const list = (value, label) => {
  if (!Array.isArray(value) || value.length > 30 || value.some(v => typeof v !== 'string' || !v.trim() || v.length > 2000)) fail(400, `${label}格式无效`);
  return value;
};
export function taskFinding(db, pipeline, id, {requireVulnerability=true} = {}) {
  if (!Number.isSafeInteger(id) || id < 1) fail(400, '发现编号无效');
  const row = dbSafe(db, 'SELECT * FROM scan_results WHERE id=?', id);
  if (!row || !pipelineScans(db, pipeline).some(s => s.scan_task_id === row.scan_task_id)) fail(404, '发现不属于任务当前扫描');
  if (requireVulnerability && resultCategory(row) !== 'vulnerability') fail(400, '请选择漏洞候选，信息或工具错误不能进入验证');
  return row;
}
function dbSafe(db, sql, ...args) { return db.prepare(sql).get(...args); }
function readablePlanContent(value) {
  const parsed=json(value,null);
  const content=parsed && typeof parsed==='object' && !Array.isArray(parsed)?parsed:{};
  const valid=typeof content.target==='string' && Array.isArray(content.steps) && content.steps.length>0
    && content.steps.every(step=>step && typeof step==='object' && !Array.isArray(step)
      && typeof step.tool_id==='string' && typeof step.args_template==='string'
      && Array.isArray(json(step.args_template,null)) && json(step.args_template,null).every(arg=>typeof arg==='string')
      && (step.payload_variables===undefined || json(step.payload_variables,null)
        && typeof json(step.payload_variables,null)==='object' && !Array.isArray(json(step.payload_variables,null))))
    && [content.missing_conditions,content.blockers].every(list=>list===undefined || Array.isArray(list) && list.every(reason=>typeof reason==='string'));
  // Read compatibility only: never repair or replace the frozen database snapshot.
  return {...content,...(!valid?{steps:[],read_error:'历史方案结构无效，保留原记录；请保存新版本后再执行'}:{}),
    provenance:content.provenance || {kind:'legacy',label:'历史来源未记录'}};
}
export function verification(db, pipeline, id, options) {
  const row = dbSafe(db, 'SELECT * FROM finding_verifications WHERE id=? AND pipeline_id=?', id, pipeline.pipeline_id);
  if (!row) fail(404, '验证项不存在');
  taskFinding(db, pipeline, row.finding_id, options);
  return row;
}
export function ensureVerification(db, pipeline, findingId) {
  const row = taskFinding(db, pipeline, findingId);
  db.prepare('INSERT INTO finding_verifications(id,pipeline_id,finding_id,scan_task_id) VALUES(?,?,?,?) ON CONFLICT(pipeline_id,finding_id) DO NOTHING')
    .run(`fv_${randomUUID()}`, pipeline.pipeline_id, findingId, row.scan_task_id);
  return dbSafe(db, 'SELECT * FROM finding_verifications WHERE pipeline_id=? AND finding_id=?', pipeline.pipeline_id, findingId);
}
export function verificationDetail(db, pipeline, id) {
  const item = verification(db, pipeline, id, {requireVulnerability:false});
  const row = taskFinding(db, pipeline, item.finding_id, {requireVulnerability:false});
  const plans = db.prepare('SELECT * FROM finding_verification_plans WHERE verification_id=? ORDER BY revision DESC').all(id)
    .map(p => ({...p, content:readablePlanContent(p.content)}));
  const attempts = db.prepare('SELECT * FROM finding_verification_attempts WHERE verification_id=? ORDER BY rowid DESC').all(id).map(a => {
    const frozen=plans.find(p=>p.revision===a.revision);
    const rulePlan={...frozen?.content,finding_id:item.finding_id};
    const summary=attemptVerificationSummary(db,item,a);
    return {...a,summary,human_opinions:summary.human_opinions,
    assessments:db.prepare('SELECT * FROM finding_verification_assessments WHERE attempt_id=? ORDER BY id').all(a.id).map(r=>({...r,evidence_ids:json(r.evidence_ids,[])})),
    reviews:db.prepare('SELECT * FROM finding_verification_reviews WHERE attempt_id=? ORDER BY id DESC').all(a.id).map(r => ({...r,evidence_ids:json(r.evidence_ids, [])})),
    evidence:db.prepare('SELECT id,step_index,tool_id,evidence_type,evidence_data,raw_stdout,raw_stderr,attempt_id FROM evidence_records WHERE run_id=? ORDER BY id').all(a.run_id)
      .map(e => ({...e, evidence_data:json(e.evidence_data), observation:verificationObservation(e),
        criteria:directoryEvidenceCriteria(rulePlan.assessment_rule,e,{...a,fingerprint:frozen?.fingerprint},rulePlan),
        raw_stdout:e.tool_id==='target-request' ? '' :/credential|password|session|cookie/i.test(e.evidence_type || '') ? '[凭据证据已隐藏]' : e.raw_stdout})),
    steps:db.prepare('SELECT step_index,tool_id,success,exit_code,notes FROM execution_steps WHERE run_id=? ORDER BY id').all(a.run_id)
  };});
  const entry=findingVerificationEntry(db,pipeline,row);
  const detail=taskDisplayValue({ ...item, task_no:pipeline.task_no || null, eligible:resultCategory(row)==='vulnerability',
    ineligibility_reason:resultCategory(row)==='vulnerability' ? null : '此记录现归为信息或非漏洞记录，仅保留历史与停止操作，不能新建验证。', default_target:entry.target,entry_context:entry, finding:publicScanRecord(row), plans, attempts,
    payloads:verificationPayloadCatalog(db,item,row,plans[0]?.content),payload_artifacts:payloadArtifactView(db,item),readiness:verificationReadiness(db,pipeline,item,plans[0]), summary:verificationSummary(db,item.finding_id,pipeline.pipeline_id) });
  // Serialize only after field-level redaction; legacy readers still receive valid JSON.
  for(const attempt of detail.attempts)for(const evidence of attempt.evidence)if(evidence.observation)evidence.raw_stdout=JSON.stringify(evidence.observation);
  return detail;
}
export function verificationSources(db,pipeline,actor,id,query={}) {
  const item=verification(db,pipeline,id),row=taskFinding(db,pipeline,item.finding_id);
  return findingSources(db,pipeline,actor,row,findingVerificationEntry(db,pipeline,row).target,query);
}
export function templatePlan(db,pipeline,actor,id,playbookId) {
  const item=verification(db,pipeline,id),row=taskFinding(db,pipeline,item.finding_id);
  return findingTemplate(db,pipeline,actor,row,findingVerificationEntry(db,pipeline,row).target,playbookId);
}
export function selectVerificationTemplate(db,pipeline,actor,id,input) {
  const draft=templatePlan(db,pipeline,actor,id,input.playbook_id);
  return saveVerificationPlan(db,pipeline,actor,id,{...draft,expected_revision:input.expected_revision},{provenance:draft.provenance,allowBlocked:true});
}
export function verificationReadiness(db,pipeline,item,record) {
  if(!record)return {ready:false,reasons:['请先选择或生成攻击测试方案']};
  const content=readablePlanContent(record.content);
  if(content.read_error)return {ready:false,reasons:[content.read_error],revision:record.revision,fingerprint:record.fingerprint};
  const reasons=[...scopeConditions(taskScope(pipeline)),...(content.missing_conditions || []),...(content.blockers || [])];
  if(resultCategory(taskFinding(db,pipeline,item.finding_id,{requireVulnerability:false}))!=='vulnerability')reasons.push('此记录仅保留历史，不可新建验证');
  if(content.verification_contract?.schema_version!==1)reasons.push('旧方案需保存新版本并重新确认');
  if(!content.success_criteria)reasons.push('缺少成功判据');if(!content.cleanup)reasons.push('缺少清理说明');
  const compiled=compilePlaybook({db,target:content.target,steps:content.steps || []});
  if(!compiled.ok)reasons.push(...compiled.errors);
  for(const step of compiled.compiledSteps){const checked=validateExecutionScope({target:content.target,toolId:step.tool_id,args:step.resolved_args,scope:taskScope(pipeline)});if(!checked.allowed)reasons.push(checked.reason);}
  if(content.steps?.some(s=>s.consumption==='pending'))reasons.push('需要为指定步骤手动选择载荷');
  if(['queued','running','cancelling','unknown'].includes(item.state))reasons.push('当前验证仍有活动调用或停止未确认');
  const count=db.prepare('SELECT count(*) n FROM finding_verification_attempts WHERE verification_id=?').get(item.id).n;
  if(count>=content.max_attempts)reasons.push('已达到此漏洞尝试上限；已有执行记录仍可查看和人工复核');
  return {ready:reasons.length===0,reasons:[...new Set(reasons)],revision:record.revision,fingerprint:record.fingerprint,attempts_used:count,max_attempts:content.max_attempts};
}
function normalizePlan(db,pipeline,item,input,actor,{allowBlocked=false}={}) {
  const target=text(input.target,'验证目标',256), scope=taskScope(pipeline);
  if(!isTargetInScope(scope,target)) fail(400,'验证目标超出任务范围');
  const source=input.source_playbook_id || null;
  if(source) assertPlaybookUse(db,source,actor,pipeline.created_by);
  if(!Array.isArray(input.steps) || !input.steps.length || input.steps.length>20) fail(400,'验证计划须有 1 至 20 个步骤');
  const row=taskFinding(db,pipeline,item.finding_id);
  const matches=findingPayloadMatches(db,row);
  const steps=input.steps.map((s,i)=>{
    const args=s.args_template;
    if(!Array.isArray(args) || args.length>100 || args.some(a=>typeof a!=='string' || a.length>16384)) fail(400,'工具参数须为有界字符串数组');
    if(!['none','internal','independent','pending'].includes(s.consumption)) fail(400,'请选择载荷消费方式');
    const step={step_index:i,step_id:typeof s.step_id==='string' && /^[a-zA-Z0-9_-]{1,100}$/.test(s.step_id)?s.step_id:`finding_step_${i}`,name:text(s.name,'步骤名称',200),tool_id:text(s.tool_id,'工具',80),
      args_template:JSON.stringify(args),description:text(s.description || s.name,'步骤说明'),expected_evidence:allowBlocked && !s.expected_evidence?'':text(s.expected_evidence,'预期证据'),
      payload_id:null,reference_payload_id:typeof s.reference_payload_id==='string'?s.reference_payload_id:null,payload_variables:{},consumption:s.consumption,payload_snapshot:null,payload_version:null};
    const variables=s.payload_variables || {};
    if(!variables || Array.isArray(variables) || typeof variables!=='object' || Object.keys(variables).length>30
      || Object.entries(variables).some(([k,v])=>!/^\w{1,64}$/.test(k)||typeof v!=='string'||v.length>2000)) fail(400,'步骤变量格式无效');
    step.payload_variables=variables;
    if(s.consumption==='independent') {
      const match=matches.matches.find(m=>m.payload_id===s.payload_id);
      const payload=match && getPayloadById(s.payload_id,db);
      if(!payload || match.availability!=='available') fail(400,'载荷不可用或不匹配当前发现');
      if(s.payload_version!==match.version) fail(409,'载荷版本已变化或未选定版本，请刷新');
      if(payload.consumption?.type!=='tool_args') fail(400,'静态参考载荷不是可执行参数，请人工编制步骤并选择无需独立载荷');
      step.payload_id=s.payload_id;step.payload_version=match.version;step.payload_snapshot=payload;
    } else if(s.payload_id) fail(400,'非独立载荷步骤不能填写载荷 ID');
    return step;
  });
  if(new Set(steps.map(s=>s.step_id)).size!==steps.length)fail(400,'步骤标识不能重复');
  const maxAttempts=input.max_attempts ?? 2, duration=input.duration_ms ?? 300000;
  if(!Number.isInteger(maxAttempts)||maxAttempts<1||maxAttempts>3||!Number.isInteger(duration)||duration<1000||duration>900000) fail(400,'尝试上限为 1–3 次，时长为 1 秒–15 分钟');
  if(/^请填写/.test(input.success_criteria || '') || /^请填写/.test(input.cleanup || '')) fail(400,'请补全成功判据和清理说明，不能保留模板提示');
  const plan={name:text(input.name,'计划名称',200),target,source_playbook_id:source,scope,
    prerequisites:list(input.prerequisites || [],'前置条件'),missing_conditions:list(input.missing_conditions || [],'缺失条件'),
    success_criteria:typeof input.success_criteria==='string'?input.success_criteria.trim().slice(0,4000):'',cleanup:typeof input.cleanup==='string'?input.cleanup.trim().slice(0,4000):'',
    max_attempts:maxAttempts,duration_ms:duration,steps};
  const objectiveDraft=normalizeVerificationObjectiveDraft(input.objective_draft);
  if(objectiveDraft)plan.objective_draft=objectiveDraft;
  // Plans never persist inline secrets; authentication must be supplied by the configured provider.
  if(JSON.stringify(taskDisplayValue(plan))!==JSON.stringify(plan)) fail(400,'计划含敏感值、过深或过量内容，请使用配置引用并缩小计划');
  const compiled=compilePlaybook({steps,target,db});
  const compileBlockers=[...compiled.errors];
  if(!compiled.ok && !allowBlocked) fail(400,compiled.errors.join('; '));
  for(const s of compiled.compiledSteps) {
    if(s.resolved_args.some(a=>/\{\{|<target>|REPLACE_ME|CHANGE_ME/.test(a))) {
      if(!allowBlocked)fail(400,'验证计划仍含未解析变量，请填写具体入口与变量');
      compileBlockers.push('步骤仍有未解析变量，请通过调整方案补齐具体输入');
    }
    const check=validateExecutionScope({target,toolId:s.tool_id,args:s.resolved_args,scope});
    if(!check.allowed){if(!allowBlocked)fail(400,check.reason);compileBlockers.push(check.reason);}
  }
  if(compileBlockers.length)plan.blockers=[...new Set(compileBlockers)];
  if(plan.steps.some(s=>s.consumption==='pending'))plan.missing_conditions=[...new Set([...plan.missing_conditions,'需要为指定步骤手动选择载荷'])];
  return plan;
}
export function saveVerificationPlan(db,pipeline,actor,id,input,{provenance,allowBlocked=false}={}) {
  return db.transaction(()=>{
    const item=verification(db,pipeline,id);
    if(['queued','running','cancelling','unknown'].includes(item.state)) fail(409,'验证活动尚未结束，不能修改计划');
    if(input.expected_revision!==item.revision) fail(409,'计划已更新，请刷新后修改');
    const content=normalizePlan(db,pipeline,item,input,actor,{allowBlocked}), revision=item.revision+1;
    const previous=db.prepare('SELECT content FROM finding_verification_plans WHERE verification_id=? AND revision=?').get(id,item.revision);
    let origin=provenance;
    if(!origin && input.source_playbook_id && input.source_playbook_id!==json(previous?.content).source_playbook_id) {
      const pb=assertPlaybookUse(db,input.source_playbook_id,actor,pipeline.created_by);
      origin={...sourceMetadata(pb),playbook_id:pb.playbook_id,playbook_fingerprint:planFingerprint(pb)};
    }
    const prior=json(previous?.content).provenance;
    if(!origin && prior)origin={...prior,kind:prior.playbook_id?'template_adjusted':'manual_adjusted',
      label:prior.playbook_id?'基于模板人工调整':'基于已有方案人工调整',original_kind:prior.original_kind || prior.kind};
    content.provenance=origin || {kind:'manual',label:'人工编制方案'};
    content.provenance.parent_revision=item.revision || null;
    const finding=taskFinding(db,pipeline,item.finding_id);
    const entry=findingVerificationEntry(db,pipeline,finding);
    const candidate=entry.target===content.target?findingRule(finding,content.target):null;
    const compatible=compiledRuleStep(db,content,candidate);
    if(compatible)content.assessment_rule=compatible;
    content.verification_contract=buildVerificationContract(content,item.finding_id);
    const blockers=[...(content.blockers || [])];
    if(!content.success_criteria)blockers.push('缺少成功判据');if(!content.cleanup)blockers.push('缺少清理说明');
    content.steps.forEach((step,i)=>{if(!step.expected_evidence)blockers.push(`步骤 ${i+1} 缺少预期证据`);});
    content.blockers=blockers;
    db.prepare('INSERT INTO finding_verification_plans(verification_id,revision,content,fingerprint) VALUES(?,?,?,?)')
      .run(id,revision,JSON.stringify(content),fingerprint(content));
    const conditions=[...scopeConditions(content.scope),...content.missing_conditions,...(content.blockers || [])];
    db.prepare('UPDATE finding_verifications SET revision=?,state=?,reason=? WHERE id=?')
      .run(revision,conditions.length?'needs_conditions':'draft',conditions.join('; ') || null,id);
    return {revision,state:conditions.length?'needs_conditions':'draft'};
  })();
}
export function checkVerificationPlan(db,pipeline,actor,id,revision) {
  const item=verification(db,pipeline,id);
  if(revision!==item.revision) fail(409,'计划版本已变化');
  const record=dbSafe(db,'SELECT * FROM finding_verification_plans WHERE verification_id=? AND revision=?',id,revision);
  if(!record) fail(409,'尚未保存计划');
  const content=json(record.content);
  if(content.verification_contract?.schema_version!==1)fail(409,'旧方案缺少验证目标契约，请保存新版本并重新确认');
  if(JSON.stringify(content.verification_contract)!==JSON.stringify(buildVerificationContract(content,item.finding_id)))fail(409,'验证目标契约不一致，请保存新版本并重新确认');
  if(fingerprint(content)!==record.fingerprint) fail(409,'计划快照不一致');
  if(JSON.stringify(content.scope)!==JSON.stringify(taskScope(pipeline))) fail(409,'任务范围已变化，请创建新计划');
  const missing=[...scopeConditions(content.scope),...content.missing_conditions,...(content.blockers || [])];
  if(missing.length) fail(409,missing.join('; '));
  normalizePlan(db,pipeline,item,{...content,steps:content.steps.map(s=>({...s,args_template:json(s.args_template,[])}))},actor);
  return {item,record,content};
}
export function confirmVerificationPlan(db,pipeline,actor,id,input) {
  const {record}=checkVerificationPlan(db,pipeline,actor,id,input.revision);
  if(input.conditions_confirmed!==true || input.criteria_confirmed!==true) fail(400,'请确认前提与成功判据');
  const item=verification(db,pipeline,id);
  if(['queued','running','cancelling','unknown'].includes(item.state)) fail(409,'验证活动尚未结束');
  db.prepare("UPDATE finding_verification_plans SET confirmed_by=?,confirmed_at=datetime('now') WHERE verification_id=? AND revision=?")
    .run(actor.sub,id,record.revision);
  db.prepare("UPDATE finding_verifications SET state='ready',reason=NULL WHERE id=?").run(id);
  return {state:'ready',revision:record.revision};
}
export function createVerificationAttempt(db,pipeline,actor,id,input) {
  return db.transaction(()=>{
    const requestId=text(input.request_id,'幂等请求编号',100);
    verification(db,pipeline,id);
    const old=dbSafe(db,'SELECT * FROM finding_verification_attempts WHERE verification_id=? AND request_id=?',id,requestId);
    if(old) return {...old,reused:true};
    const {item,record,content}=checkVerificationPlan(db,pipeline,actor,id,input.revision);
    if(!record.confirmed_at) fail(409,'请先确认计划');
    if(dbSafe(db,"SELECT 1 FROM finding_verification_attempts WHERE pipeline_id=? AND state IN ('queued','running','cancelling','unknown')",pipeline.pipeline_id)) fail(409,'本任务还有活动验证或未确认停止的调用');
    if(pipeline.status==='running' || (pipeline.run_id && dbSafe(db,"SELECT 1 FROM execution_runs WHERE run_id=? AND status IN ('PENDING','RUNNING')",pipeline.run_id))) fail(409,'任务主流程仍在运行');
    const count=dbSafe(db,'SELECT count(*) n FROM finding_verification_attempts WHERE verification_id=?',id).n;
    if(count>=content.max_attempts) fail(409,'已达到此漏洞的尝试上限');
    const attemptId=`fva_${randomUUID()}`,runId=`run_${randomUUID()}`,pbId=`fv_plan_${randomUUID()}`;
    const linkage={verification_id:id,finding_id:item.finding_id,pipeline_id:pipeline.pipeline_id,scan_task_id:item.scan_task_id,
      revision:record.revision,fingerprint:record.fingerprint,attempt_id:attemptId,duration_ms:content.duration_ms};
    db.prepare(`INSERT INTO playbooks(playbook_id,name,description,target_type,metadata,is_generated,generated_from,disable_auto_insert,roles_allowed)
      VALUES(?,?,?,?,?,1,?,1,'["admin","user"]')`).run(pbId,content.name,content.success_criteria,
      JSON.stringify([content.target.startsWith('tcp:')?'tcp_service':/^https?:/.test(content.target)?'web_url':'host']),
      JSON.stringify({finding_verification:linkage}),item.scan_task_id);
    const insert=db.prepare(`INSERT INTO playbook_steps(playbook_id,step_index,step_id,name,tool_id,args_template,description,payload_id,payload_variables,evidence_config,optional)
      VALUES(?,?,?,?,?,?,?,?,?,?,0)`);
    content.steps.forEach(s=>insert.run(pbId,s.step_index,s.step_id,s.name,s.tool_id,s.args_template,s.description,s.payload_id,
      JSON.stringify(s.payload_variables),JSON.stringify({finding_verification:linkage,expected_evidence:s.expected_evidence,consumption:s.consumption,
        payload_snapshot:s.payload_snapshot,payload_version:s.payload_version})));
    db.prepare(`INSERT INTO execution_runs(run_id,playbook_id,user_sub,user_role,target,scan_task_id,status,engine_type,plan_data,created_at,updated_at)
      VALUES(?,?,?,?,?,?,'PENDING','mechanical',?,datetime('now'),datetime('now'))`)
      .run(runId,pbId,pipeline.created_by,actor.role,content.target,item.scan_task_id,JSON.stringify({finding_verification:linkage}));
    db.prepare("INSERT INTO finding_verification_attempts(id,verification_id,pipeline_id,revision,run_id,request_id,state) VALUES(?,?,?,?,?,?,'queued')")
      .run(attemptId,id,pipeline.pipeline_id,record.revision,runId,requestId);
    db.prepare("UPDATE finding_verifications SET state='queued',reason=NULL WHERE id=?").run(id);
    return dbSafe(db,'SELECT * FROM finding_verification_attempts WHERE id=?',attemptId);
  })();
}
export function reviewVerification(db,pipeline,actor,id,input) {
  const item=verification(db,pipeline,id);
  const attempt=dbSafe(db,'SELECT * FROM finding_verification_attempts WHERE id=? AND verification_id=?',input.attempt_id,id);
  if(!attempt || !attempt.stop_confirmed || !['completed','failed','aborted'].includes(attempt.state)) fail(409,'请选择已停止的验证尝试');
  if(!['confirmed','not_verified','inconclusive','false_positive'].includes(input.conclusion)) fail(400,'结论无效');
  const frozen=dbSafe(db,'SELECT fingerprint FROM finding_verification_plans WHERE verification_id=? AND revision=?',id,attempt.revision);
  const ids=input.evidence_ids;
  if(!Array.isArray(ids)||!ids.length||ids.length>20||ids.some(n=>!Number.isSafeInteger(n))) fail(400,'请引用实际证据');
  for(const evidenceId of ids) {
    const evidence=dbSafe(db,'SELECT * FROM evidence_records WHERE id=? AND run_id=?',evidenceId,attempt.run_id);
    const link=json(evidence?.evidence_data).finding_verification;
    if(!link || link.finding_id!==item.finding_id || link.attempt_id!==attempt.id || link.revision!==attempt.revision
      || link.verification_id!==id || link.pipeline_id!==pipeline.pipeline_id || !frozen || link.fingerprint!==frozen.fingerprint) fail(400,'证据不属于此漏洞与本次尝试');
  }
  const note=text(input.note,'判断依据');
  db.prepare('INSERT INTO finding_verification_reviews(attempt_id,conclusion,evidence_ids,note,reviewed_by) VALUES(?,?,?,?,?)')
    .run(attempt.id,input.conclusion,JSON.stringify([...new Set(ids)]),taskDisplayValue(note),actor.sub);
  return verificationSummary(db,item.finding_id,pipeline.pipeline_id);
}

function compiledRuleStep(db,content,rule) {
  if(!rule)return null;
  const compiled=compilePlaybook({db,target:content.target,steps:content.steps});
  const step=compiled.compiledSteps.find(s=>{
    if(s.tool_id!=='target-request'||s.compile_status!=='READY')return false;
    const spec=json(s.resolved_args[0]);return spec.url===rule.target && (spec.method || 'GET')==='GET';
  });
  return step?{...rule,step_id:step.step_id}:null;
}
export function confirmAndStart(db,pipeline,actor,id,input) {
  return db.transaction(()=>{
    verification(db,pipeline,id);
    const existing=db.prepare('SELECT * FROM finding_verification_attempts WHERE verification_id=? AND request_id=?').get(id,input.request_id || '');
    if(existing)return {...existing,reused:true};
    const record=db.prepare('SELECT * FROM finding_verification_plans WHERE verification_id=? AND revision=?').get(id,input.revision);
    if(!record||record.fingerprint!==input.fingerprint)fail(409,'展示的方案版本或内容已变化，请刷新后确认');
    confirmVerificationPlan(db,pipeline,actor,id,{revision:input.revision,conditions_confirmed:input.confirmed===true,criteria_confirmed:input.confirmed===true});
    return createVerificationAttempt(db,pipeline,actor,id,input);
  })();
}
export function changeStepPayload(db,pipeline,actor,id,input,unbind=false) {
  return db.transaction(()=>{
    const item=verification(db,pipeline,id);
    if(item.revision!==input.expected_revision)fail(409,'方案版本已变化');
    const record=db.prepare('SELECT content FROM finding_verification_plans WHERE verification_id=? AND revision=?').get(id,item.revision);
    if(!record)fail(409,'请先选择方案');
    const content=json(record.content);const step=content.steps.find(s=>s.step_id===input.step_id);
    if(!step)fail(400,'步骤不属于当前方案');
    const oldId=step.payload_id,oldVersion=step.payload_version;
    if(unbind) {
      if(!oldId)fail(400,'当前步骤没有已绑定载荷');
      step.payload_id=null;step.payload_snapshot=null;step.payload_version=null;step.consumption='pending';
    } else {
      const row=taskFinding(db,pipeline,item.finding_id);
      const matches=findingPayloadMatches(db,row).matches;
      if(!matches.some(m=>m.payload_id===input.payload_id))fail(400,'载荷不匹配此发现');
      const payload=getPayloadById(input.payload_id,db);
      validateBoundPayload(db,step,payload,input.version,content.target,content.scope);
      step.payload_id=payload.id;step.payload_version=input.version;step.payload_snapshot=payload;step.consumption='independent';
    }
    content.missing_conditions=content.missing_conditions.filter(v=>v!=='需要为指定步骤手动选择载荷');
    const result=saveVerificationPlan(db,pipeline,actor,id,{...content,expected_revision:item.revision,steps:content.steps.map(s=>({...s,args_template:json(s.args_template,[])}))},{allowBlocked:unbind,provenance:content.provenance});
    db.prepare('INSERT INTO finding_payload_events(verification_id,action,payload_id,payload_version,revision,step_id,actor) VALUES(?,?,?,?,?,?,?)')
      .run(id,unbind?'unbound':'bound',unbind?oldId:input.payload_id,unbind?oldVersion:input.version,result.revision,input.step_id,actor.sub);
    return result;
  })();
}
