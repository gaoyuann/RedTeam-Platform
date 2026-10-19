import { taskDisplayValue } from './taskExecution.js';
import { getPayloadById } from './payloadLoader.js';
import { findingPayloadMatches,payloadVersion } from './findingPayloads.js';
import { resolveFindingPayload } from './findingPayloadResolver.js';
import { compilePlaybook } from './playbookCompiler.js';
import { validateExecutionScope } from './executionScope.js';
import { taskScope } from './taskScope.js';
const parse=v=>{try{return typeof v==='string'?JSON.parse(v):v;}catch{return null;}};
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status});};
export function payloadPreview(payload,target) {
  const args=payload.consumption?.args_template;
  const fields=[];
  if(payload.consumption?.tool_id==='target-request' && Array.isArray(args)) {
    const spec=parse(args[0]?.replaceAll('<target>',target || '<target>'));
    if(spec){fields.push({label:'位置',value:spec.url || ''},{label:'方法',value:spec.method || 'TCP 交互'});
      if(spec.body)fields.push({label:'测试输入',value:spec.body});
      if(spec.exchanges)fields.push({label:'交互输入',value:spec.exchanges.map(e=>e.send).join('\n')});
    }
  } else if(Array.isArray(args)) args.forEach((value,i)=>fields.push({label:`参数 ${i+1}`,value}));
  else for(const record of (payload.execution || payload.commands || []).slice(0,5))fields.push({label:'参考内容（不可直接执行）',value:record.command || ''});
  return taskDisplayValue(fields);
}
export function verificationPayloadCatalog(db,item,row,plan) {
  const {matches,links}=findingPayloadMatches(db,row);
  const events=db.prepare('SELECT * FROM finding_payload_events WHERE verification_id=? ORDER BY id').all(item.id);
  return {matches:matches.map(match=>{
    const payload=getPayloadById(match.payload_id,db);
    const generated=events.some(e=>e.action==='generated' && e.payload_id===match.payload_id && e.payload_version===match.version);
    return {...match,provenance:payload?._type==='ai_generated'?'ai':'library',created_here:generated,
      tool_id:payload?.consumption?.tool_id || null,preview:payloadPreview(payload || {},plan?.target),
      compatible_steps:(plan?.steps || []).map(step=>({step_id:step.step_id,name:step.name,
        compatible:match.consumption==='tool_args' && payload?.consumption?.tool_id===step.tool_id,
        reason:match.consumption!=='tool_args'?'仅为参考样本':payload?.consumption?.tool_id!==step.tool_id?'工具不兼容':''}))};
  }),links,events:taskDisplayValue(events)};
}
export function validateBoundPayload(db,step,payload,version,target,scope) {
  if(!payload || payloadVersion(payload)!==version)fail('载荷已变更或不可用，请刷新',409);
  if(payload.consumption?.type!=='tool_args')fail('此样本仅供参考，不可绑定执行');
  if(payload.consumption.tool_id!==step.tool_id)fail('载荷工具与步骤不兼容');
  const compiled=compilePlaybook({db,target,steps:[{...step,payload_id:payload.id,payload_snapshot:payload,payload_version:version}]});
  if(!compiled.ok)fail(compiled.errors.join('; '));
  const check=validateExecutionScope({target,toolId:step.tool_id,args:compiled.compiledSteps[0].resolved_args,scope});
  if(!check.allowed)fail(check.reason);
}
export async function prepareVerificationPayload(db,pipeline,actor,item,row,plan,input,dependencies={}) {
  const step=plan.steps.find(s=>s.step_id===input.step_id);
  if(!step)fail('请先选择当前方案内的步骤');
  const result=await resolveFindingPayload(db,item.finding_id,actor,{tool_id:step.tool_id,target:plan.target,
    bindFinding:false,generate:dependencies.generatePayload,
    constraints:{step_name:step.name,expected_evidence:step.expected_evidence,variables:step.payload_variables || {}}});
  const canonical=getPayloadById(result.payload.id,db);
  validateBoundPayload(db,step,canonical,result.catalog_version,plan.target,taskScope(pipeline));
  const latest=db.prepare('SELECT revision,state FROM finding_verifications WHERE id=?').get(item.id);
  if(latest?.revision!==item.revision || ['queued','running','cancelling','unknown'].includes(latest?.state))fail('方案或执行状态已变化；载荷已存库但未绑定，请刷新',409);
  // This records preparation only. Binding always requires a separate user choice.
  db.prepare('INSERT INTO finding_payload_events(verification_id,action,payload_id,payload_version,revision,step_id,actor) VALUES(?,?,?,?,?,?,?)')
    .run(item.id,result.state==='generated'?'generated':'reused',result.payload.id,result.catalog_version,item.revision,step.step_id,actor.sub);
  return {state:result.state,payload_id:result.payload.id,version:result.catalog_version,preview:payloadPreview(result.payload,plan.target),bound:false};
}
