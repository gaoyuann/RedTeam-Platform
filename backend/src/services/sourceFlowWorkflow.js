import {randomUUID} from 'node:crypto';
import {cscanTarget,cscanNotes} from './cscanTarget.js';
import {sourceTarget} from './sourceScanConnections.js';
import {normalizeTaskScope} from './taskScope.js';
import {creationHash,validateCreationRequest,insertNumberedTask} from './taskIdentity.js';

// Persist before dispatch. Repeated requests never resubmit an uncertain Flow.
export function createSourceFlowTask(db,actor,input={}) {
  if(input.authorization_confirmed!==true)throw Object.assign(new Error('请确认本次源码审计目标已获授权'),{status:400});
  validateCreationRequest(input.request_id);
  if(!input.request_id)throw Object.assign(new Error('缺少创建请求编号'),{status:400});
  const target=cscanTarget(input.target);
  const runtime=input.runtime_target?sourceTarget(input.runtime_target):null;
  const config={test_type:'source',input_kind:'agent',cscan_target:target,
    source_notes:cscanNotes(input.notes || ''),runtime_target:runtime,
    authorization_confirmed:true,authorization_scope:target,task_name:'源码审计 · '+target,
    source_workflow:'pentagi-target-flow-v1'};
  config.task_scope=normalizeTaskScope({task_scope:{includes:[target,...(runtime?[runtime]:[])]}},target);
  const hash=creationHash(config);
  return db.transaction(()=>{
    const {row,reused}=insertNumberedTask(db,{target,config,owner:actor.sub,ownerRole:actor.role,
      requestId:input.request_id,hash});
    let scan=row.scan_task_id && db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(row.scan_task_id);
    if(reused && !scan)throw Object.assign(new Error('原任务扫描记录缺失，请核对原任务'),{status:409});
    if(!reused) {
      const id='scan_'+randomUUID();
      db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,parameters,created_by,pipeline_id) VALUES(?,?,'source_scan','PENDING',?,?,?)")
        .run(id,target,JSON.stringify({input_kind:'agent',cscan_target:target,source_notes:config.source_notes,runtime_target:runtime}),actor.sub,row.pipeline_id);
      db.prepare("UPDATE pipelines SET scan_task_id=?,status='running' WHERE pipeline_id=?").run(id,row.pipeline_id);
      scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(id);
    }
    return {pipeline_id:row.pipeline_id,task_no:row.task_no,scan_task_id:scan.scan_task_id,target,reused};
  }).immediate();
}

export async function dispatchSourceFlow(db,record,executeScan) {
  if(record.reused)return;
  try {
    await executeScan(record.scan_task_id);
  } catch {
    db.prepare("UPDATE scan_tasks SET status='FAILED',error_message='扫描调度失败，请核对原 Flow；不会自动重发' WHERE scan_task_id=? AND status IN ('PENDING','RUNNING')")
      .run(record.scan_task_id);
  } finally {
    const scan=db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id=?').get(record.scan_task_id);
    const state=['COMPLETED','PARTIAL'].includes(scan?.status)?'completed':scan?.status==='CANCELLED'?'aborted':'failed';
    db.prepare("UPDATE pipelines SET status=?,updated_at=datetime('now') WHERE pipeline_id=? AND status='running'")
      .run(state,record.pipeline_id);
  }
}
