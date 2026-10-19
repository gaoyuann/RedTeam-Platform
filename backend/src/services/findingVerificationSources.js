import { getPayloadById } from './payloadLoader.js';
import { createHash } from 'node:crypto';
import { matchPlaybooks } from './playbookMatcher.js';
import { resolveTargetProfile,checkTargetTypeCompatibility } from './targetProfileResolver.js';
import { canReadPlaybook,playbookScope,assertPlaybookUse } from './playbookAccess.js';
import { findingRule } from './findingVerificationRules.js';
import { compilePlaybook } from './playbookCompiler.js';
import { taskScope } from './taskScope.js';
import { validateExecutionScope } from './executionScope.js';

const json=(v,f={})=>{try{return typeof v==='string'?JSON.parse(v):v??f;}catch{return f;}};
export const planFingerprint=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export function sourceMetadata(pb) {
  if(json(pb.metadata).finding_template)return {kind:'builtin',label:'内置定向方案'};
  if(pb.is_generated)return {kind:'historical_ai',label:'历史 AI 方案'};
  if(pb.generated_from==='imported'||!pb.author)return {kind:'builtin',label:'内置模板'};
  return {kind:'manual_template',label:'人工编制模板'};
}
export function findingSources(db,pipeline,actor,row,target,query={}) {
  const profile=resolveTargetProfile(target || pipeline.target);
  const ranked=matchPlaybooks([row],profile,{target,db});
  const byId=new Map(ranked.map(r=>[r.playbook_id,r]));
  const rule=findingRule(row,target);
  const browse=query.mode==='all';
  const q=String(query.q || '').toLowerCase().slice(0,100);
  const items=[];
  for(const pb of db.prepare('SELECT * FROM playbooks ORDER BY name').all()) {
    const scope=playbookScope(db,pb);
    if(!canReadPlaybook(db,pb,actor) || scope.snapshot || scope.private && scope.owner!==pipeline.created_by)continue;
    const steps=db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(pb.playbook_id);
    if(!steps.length || steps.length>20)continue;
    if(q&&!`${pb.name} ${pb.description || ''}`.toLowerCase().includes(q))continue;
    const built=json(pb.metadata).finding_template;
    const matched=byId.get(pb.playbook_id);
    const directional=built && rule && built.id===rule.id;
    const candidate=directional||!!matched;
    if(!browse&&!candidate)continue;
    const compiled=compilePlaybook({steps,target,db});
    if(compiled.compiledSteps.some(s=>s.compile_status==='BLOCKED_MISSING_TOOLSPEC'))continue;
    const conditions=[...(matched?.match_conditions || [])];
    const compatibility=checkTargetTypeCompatibility(json(pb.target_type,[]),profile.target_class);
    if(!compatibility.ok)conditions.push('方案目标类型与当前入口不兼容');
    if(!compiled.ok)conditions.push(...compiled.errors);
    for(const s of compiled.compiledSteps) {
      const checked=validateExecutionScope({target,toolId:s.tool_id,args:s.resolved_args,scope:taskScope(pipeline)});
      if(!checked.allowed)conditions.push(checked.reason);
    }
    const literalSteps=steps.some(s=>/REPLACE_ME|CHANGE_ME|\{\{/.test(s.args_template || ''));
    if(literalSteps)conditions.push('需补充步骤变量和具体输入');
    if(!directional && !json(pb.metadata).verification?.success_criteria)conditions.push('需核对或补充此漏洞的成功判据与清理条件');
    const status=directional?'directional_candidate':matched && matched.match_stage==='verification'?'directional_candidate':'reference';
    items.push({playbook_id:pb.playbook_id,name:pb.name,description:pb.description || '',source:sourceMetadata(pb),
      status:conditions.length?'needs_conditions':status,match_basis:directional?'当前发现类型对应平台定向检查判据':matched?.match_reason || '可访问的其他方案；尚无此发现的适用性证据',
      missing_conditions:[...new Set(conditions)],step_count:steps.length,
      steps:steps.map(s=>({name:s.name,tool_id:s.tool_id,description:s.description || ''})),rank:directional?10000:matched?.match_score || 0});
  }
  items.sort((a,b)=>b.rank-a.rank||a.playbook_id.localeCompare(b.playbook_id));
  const offset=Number(query.offset ?? 0),limit=Number(query.limit ?? 20);
  if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(limit)||limit<1||limit>100)throw Object.assign(new Error('方案分页参数无效'),{status:400});
  return {items:items.slice(offset,offset+limit).map(({rank,...item})=>item),total:items.length,offset,limit};
}
export function findingTemplate(db,pipeline,actor,row,target,playbookId) {
  const pb=assertPlaybookUse(db,playbookId,actor,pipeline.created_by),metadata=json(pb.metadata);
  const builtin=metadata.finding_template;
  if(builtin && findingRule(row,target)?.id!==builtin.id)throw Object.assign(new Error('该定向方案不适用于此发现'),{status:400});
  const contract=metadata.verification || {};
  const missing=[];
  if(!target)missing.push('尚缺具体服务入口');
  const steps=db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(playbookId).map(s=>{
    const evidence=json(s.evidence_config);
    const referenced=s.payload_id?getPayloadById(s.payload_id,db):null;
    const needsPayload=s.payload_id && (!referenced || referenced.consumption?.type==='tool_args');
    const args=json(s.args_template,[]);
    const actual=args.map(a=>s.tool_id==='target-request'?a.replaceAll('<target>',target || ''):a);
    return {name:s.name,tool_id:s.tool_id,args_template:actual,description:s.description || s.name,
      payload_id:null,payload_variables:json(s.payload_variables),consumption:needsPayload?'pending':'none',
      expected_evidence:evidence.expected_evidence || builtin?.expected_evidence || '',
      suggested_payload_id:s.payload_id || null,reference_payload_id:referenced && !needsPayload?s.payload_id:null};
  });
  return {name:pb.name,target:target || pipeline.target,source_playbook_id:pb.playbook_id,
    prerequisites:contract.prerequisites || ['确认本入口属于授权测试范围'],missing_conditions:[...missing,...(contract.missing_conditions || [])],
    success_criteria:contract.success_criteria || builtin?.success_criteria || '',cleanup:contract.cleanup || builtin?.cleanup || '',
    max_attempts:2,duration_ms:300000,steps,
    provenance:{...sourceMetadata(pb),playbook_id:pb.playbook_id,playbook_fingerprint:planFingerprint({pb,steps})}};
}
