import { loadFindingContext,findReusablePayload,findingPayloadCategory } from './findingPayload.js';
import { matchPayloads,payloadVersion,bindFindingPayload } from './findingPayloads.js';
import { getPayloadById,refreshPayloadIndex } from './payloadLoader.js';
const pendingByDb=new WeakMap();
export async function resolveFindingPayload(db,findingId,actor,{tool_id,target,constraints={},generate,bindFinding=true}={}) {
  const context=loadFindingContext(db,findingId,actor);
  if(target){context.target=target;context.target_type=/^(?:https?|tcp):/.test(target)?'web':context.target_type;}
  const row=db.prepare('SELECT * FROM scan_results WHERE id=?').get(findingId);
  const references=matchPayloads(db,row).filter(m=>m.consumption!=='tool_args').slice(0,3).map(m=>({id:m.payload_id,name:m.name,match_basis:m.match_basis}));
  const reusable=()=>{
    if(!tool_id)return findReusablePayload(db,context);
    for(const m of matchPayloads(db,row)) {
      const payload=getPayloadById(m.payload_id,db);
      if(payload?.applicability?.signature===context.signature && payload?.consumption?.type==='tool_args' && payload.consumption.tool_id===tool_id)return {payload,match_reason:'当前漏洞上下文与步骤工具均兼容'};
    }
    return null;
  };
  let resolved=reusable();let state='existing';
  if(!resolved) {
    let pending=pendingByDb.get(db);if(!pending){pending=new Map();pendingByDb.set(db,pending);}
    const key=context.signature+':'+(tool_id || 'any');
    let job=pending.get(key);
    if(!job){
      job=(async()=>{
        const again=reusable();if(again)return {...again,state:'existing'};
        const generator=generate || (await import('./payloadGenerator.js')).generatePayload;
        const result=await generator({category:findingPayloadCategory(context),target_type:context.target_type,findingContext:context,
          constraints:{...constraints,...(tool_id?{required_tool_id:tool_id}:{})},createdBy:actor.sub,db});
        if(!result.ok)throw Object.assign(new Error(result.status===422?'生成结果校验失败，未绑定到步骤':'载荷生成失败，未绑定到步骤'),{status:result.status || 422});
        refreshPayloadIndex(db);
        return {payload:result.payload,state:'generated',match_reason:'本次按漏洞上下文与步骤约束生成，尚未进行实际验证'};
      })().finally(()=>pending.delete(key));pending.set(key,job);
    }
    resolved=await job;state=resolved.state;
  }
  const payload=getPayloadById(resolved.payload.id,db);
  if(!payload)throw Object.assign(new Error('载荷保存后未能读取'),{status:500});
  if(tool_id && payload.consumption?.tool_id!==tool_id)throw Object.assign(new Error('载荷工具与所选步骤不兼容，未绑定'),{status:422});
  const version=payloadVersion(payload);
  if(bindFinding)bindFindingPayload(db,row,payload.id,version,actor.sub);
  return {state,finding_id:findingId,payload:{...payload,...(payload._type==='ai_generated'?{import_status:'accepted'}:{})},catalog_version:version,reference_payloads:references,match_reason:resolved.match_reason};
}
