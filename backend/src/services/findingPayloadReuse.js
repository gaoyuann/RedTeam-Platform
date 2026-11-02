import {getPayloadIndex} from './payloadLoader.js';
import {findingSignature} from './findingPayload.js';
import {validateGeneratedPayload} from './payloadGenerator.js';
import {taskDisplayValue} from './taskExecution.js';

// Category matches remain references. Automatic reuse requires the same finding
// signature and a tool contract that is still valid for the current target.
export function reusableLibraryPayload(db,row) {
  const signature=findingSignature(db,row);
  if(!signature)return null;
  const target=row.target || db.prepare('SELECT target FROM scan_tasks WHERE scan_task_id=?').get(row.scan_task_id)?.target || '';
  const type=/^(?:https?|tcp):\/\//i.test(target) || ['web_vuln','sql_injection'].includes(row.result_type)?'web':'intranet';
  for(const payload of Object.values(getPayloadIndex(db))) {
    if(payload?.applicability?.signature!==signature || payload.consumption?.type!=='tool_args')continue;
    if(validateGeneratedPayload({name:payload.name,tool_id:payload.consumption.tool_id,args:payload.consumption.args_template},type,target).length)continue;
    return payload;
  }
  return null;
}

export function libraryPayloadItems(payload) {
  if(!payload)return [];
  return [{id:'library:'+payload.id,name:(typeof payload.name==='string'?payload.name:payload.name?.zh || payload.name?.en || payload.id)+'.json',
    language:'json',code:JSON.stringify(taskDisplayValue(payload.consumption),null,2),origin:'library',payload_id:payload.id,
    purpose:'复用载荷库中与当前漏洞上下文一致的结构化工具参数',
    usage:'在“漏洞与测试”的高级设置中选择兼容步骤并绑定此载荷；确认开始测试后才执行。',
    execution_supported:false,runtime_verified:false}];
}
