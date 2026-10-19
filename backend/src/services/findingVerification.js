import { findingVerificationEntry } from './findingVerificationEntry.js';
import { verificationSummary } from './findingVerificationSummary.js';
import { randomUUID, createHash } from 'node:crypto';
import { pipelineScans } from './scanResultQuery.js';
import { publicScanRecord, resultCategory } from './scanResultCatalog.js';
import { taskDisplayValue } from './taskExecution.js';
import { taskScope, isTargetInScope, scopeConditions } from './taskScope.js';
import { validateExecutionScope } from './executionScope.js';
import { assertPlaybookUse, canReadPlaybook, playbookScope } from './playbookAccess.js';
import { getPayloadById } from './payloadLoader.js';
import { payloadVersion, findingPayloadMatches } from './findingPayloads.js';
import { compilePlaybook } from './playbookCompiler.js';

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
    .map(p => ({...p, content:json(p.content)}));
  const attempts = db.prepare('SELECT * FROM finding_verification_attempts WHERE verification_id=? ORDER BY rowid DESC').all(id).map(a => ({...a,
    reviews:db.prepare('SELECT * FROM finding_verification_reviews WHERE attempt_id=? ORDER BY id DESC').all(a.id).map(r => ({...r,evidence_ids:json(r.evidence_ids, [])})),
    evidence:db.prepare('SELECT id,step_index,tool_id,evidence_type,evidence_data,raw_stdout,raw_stderr,attempt_id FROM evidence_records WHERE run_id=? ORDER BY id').all(a.run_id)
      .map(e => ({...e, evidence_data:json(e.evidence_data), raw_stdout:/credential|password|session|cookie/i.test(e.evidence_type || '') ? '[凭据证据已隐藏]' : e.raw_stdout})),
    steps:db.prepare('SELECT step_index,tool_id,success,exit_code,notes FROM execution_steps WHERE run_id=? ORDER BY id').all(a.run_id)
  }));
  const entry=findingVerificationEntry(db,pipeline,row);
  return taskDisplayValue({ ...item, eligible:resultCategory(row)==='vulnerability',
    ineligibility_reason:resultCategory(row)==='vulnerability' ? null : '此记录现归为信息或非漏洞记录，仅保留历史与停止操作，不能新建验证。', default_target:entry.target,entry_context:entry, finding:publicScanRecord(row), plans, attempts,
    payloads:findingPayloadMatches(db,row), summary:verificationSummary(db,item.finding_id,pipeline.pipeline_id) });
}
export function verificationSources(db, pipeline, actor, id) {
  const item = verification(db,pipeline,id);
  const row = taskFinding(db,pipeline,item.finding_id);
  const haystack = JSON.stringify(publicScanRecord(row)).toLowerCase();
  return db.prepare('SELECT * FROM playbooks ORDER BY name').all().filter(p => canReadPlaybook(db,p,actor) && !playbookScope(db,p).snapshot)
    .map(p => ({playbook_id:p.playbook_id,name:p.name,description:p.description,
      score:(p.name+' '+(p.description || '')).toLowerCase().split(/[^a-z0-9\u4e00-\u9fff]+/).filter(w => w.length>3 && haystack.includes(w)).length,
      basis:'文本相关性仅供选择，须核对漏洞入口、步骤和成功判据'})).sort((a,b)=>b.score-a.score);
}
export function templatePlan(db,pipeline,actor,id,playbookId) {
  verification(db,pipeline,id);
  const pb=assertPlaybookUse(db,playbookId,actor,pipeline.created_by);
  return {name:pb.name,target:pipeline.target,source_playbook_id:pb.playbook_id,prerequisites:[],missing_conditions:[],
    success_criteria:'请填写此漏洞的可观察判据、正常对照及判定限制', cleanup:'请填写清理动作或说明无需清理',
    max_attempts:2,duration_ms:300000,
    steps:db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(playbookId).map(s=>({
      name:s.name,tool_id:s.tool_id,args_template:json(s.args_template,[]),description:s.description || s.name,
      payload_id:s.payload_id || null,payload_variables:json(s.payload_variables),
      consumption:s.payload_id ? 'independent' : 'none',expected_evidence:'请填写本步骤预期证据',
    }))};
}
function normalizePlan(db,pipeline,item,input,actor) {
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
    if(!['none','internal','independent'].includes(s.consumption)) fail(400,'请选择载荷消费方式');
    const step={step_index:i,step_id:`finding_step_${i}`,name:text(s.name,'步骤名称',200),tool_id:text(s.tool_id,'工具',80),
      args_template:JSON.stringify(args),description:text(s.description || s.name,'步骤说明'),expected_evidence:text(s.expected_evidence,'预期证据'),
      payload_id:null,payload_variables:{},consumption:s.consumption,payload_snapshot:null,payload_version:null};
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
  const maxAttempts=input.max_attempts ?? 2, duration=input.duration_ms ?? 300000;
  if(!Number.isInteger(maxAttempts)||maxAttempts<1||maxAttempts>3||!Number.isInteger(duration)||duration<1000||duration>900000) fail(400,'尝试上限为 1–3 次，时长为 1 秒–15 分钟');
  if(/^请填写/.test(input.success_criteria || '') || /^请填写/.test(input.cleanup || '')) fail(400,'请补全成功判据和清理说明，不能保留模板提示');
  const plan={name:text(input.name,'计划名称',200),target,source_playbook_id:source,scope,
    prerequisites:list(input.prerequisites || [],'前置条件'),missing_conditions:list(input.missing_conditions || [],'缺失条件'),
    success_criteria:text(input.success_criteria,'成功判据'),cleanup:text(input.cleanup,'清理说明'),
    max_attempts:maxAttempts,duration_ms:duration,steps};
  // Plans never persist inline secrets; authentication must be supplied by the configured provider.
  if(JSON.stringify(taskDisplayValue(plan))!==JSON.stringify(plan)) fail(400,'计划含敏感值、过深或过量内容，请使用配置引用并缩小计划');
  const compiled=compilePlaybook({steps,target,db});
  if(!compiled.ok) fail(400,compiled.errors.join('; '));
  for(const s of compiled.compiledSteps) {
    if(s.resolved_args.some(a=>/\{\{|<target>|REPLACE_ME|CHANGE_ME/.test(a))) fail(400,'验证计划仍含未解析变量，请填写具体入口与变量');
    const check=validateExecutionScope({target,toolId:s.tool_id,args:s.resolved_args,scope});
    if(!check.allowed) fail(400,check.reason);
  }
  return plan;
}
export function saveVerificationPlan(db,pipeline,actor,id,input) {
  return db.transaction(()=>{
    const item=verification(db,pipeline,id);
    if(['queued','running','cancelling','unknown'].includes(item.state)) fail(409,'验证活动尚未结束，不能修改计划');
    if(input.expected_revision!==item.revision) fail(409,'计划已更新，请刷新后修改');
    const content=normalizePlan(db,pipeline,item,input,actor), revision=item.revision+1;
    db.prepare('INSERT INTO finding_verification_plans(verification_id,revision,content,fingerprint) VALUES(?,?,?,?)')
      .run(id,revision,JSON.stringify(content),fingerprint(content));
    const conditions=[...scopeConditions(content.scope),...content.missing_conditions];
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
  if(fingerprint(content)!==record.fingerprint) fail(409,'计划快照不一致');
  if(JSON.stringify(content.scope)!==JSON.stringify(taskScope(pipeline))) fail(409,'任务范围已变化，请创建新计划');
  normalizePlan(db,pipeline,item,{...content,steps:content.steps.map(s=>({...s,args_template:json(s.args_template,[])}))},actor);
  const missing=[...scopeConditions(content.scope),...content.missing_conditions];
  if(missing.length) fail(409,missing.join('; '));
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
  const ids=input.evidence_ids;
  if(!Array.isArray(ids)||!ids.length||ids.length>20||ids.some(n=>!Number.isSafeInteger(n))) fail(400,'请引用实际证据');
  for(const evidenceId of ids) {
    const evidence=dbSafe(db,'SELECT * FROM evidence_records WHERE id=? AND run_id=?',evidenceId,attempt.run_id);
    const link=json(evidence?.evidence_data).finding_verification;
    if(!link || link.finding_id!==item.finding_id || link.attempt_id!==attempt.id || link.revision!==attempt.revision) fail(400,'证据不属于此漏洞与本次尝试');
  }
  const note=text(input.note,'判断依据');
  db.prepare('INSERT INTO finding_verification_reviews(attempt_id,conclusion,evidence_ids,note,reviewed_by) VALUES(?,?,?,?,?)')
    .run(attempt.id,input.conclusion,JSON.stringify([...new Set(ids)]),taskDisplayValue(note),actor.sub);
  return verificationSummary(db,item.finding_id,pipeline.pipeline_id);
}
