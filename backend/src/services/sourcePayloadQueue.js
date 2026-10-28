import {ensureVerification} from './findingVerification.js';
import {startPayloadCollection,waitPayloadArtifacts,payloadArtifactView} from './findingPayloadArtifacts.js';

const workers=new WeakMap();
export function enqueueSourcePayloads(db,scanId,dependencies={}) {
  const scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(scanId);
  if(!scan || !['COMPLETED','PARTIAL'].includes(scan.status) || !scan.pipeline_id)return Promise.resolve();
  if(!db.prepare("SELECT 1 FROM scan_results WHERE scan_task_id=? AND result_type='source_finding'").get(scanId))return Promise.resolve();
  db.prepare('INSERT OR IGNORE INTO source_payload_queue(scan_task_id) VALUES(?)').run(scanId);
  if(dependencies.defer)return Promise.resolve();
  return resumeSourcePayloads(db,dependencies);
}

// One worker per backend; persisted cursor survives restart. Only explicitly queued
// scans resume: boot never submits assistants for all historical imported scans.
export function resumeSourcePayloads(db,dependencies={}) {
  if(workers.has(db))return workers.get(db);
  const work=(async()=>{
    // Yield so the promise is registered before work can finish.
    await Promise.resolve();
    for(;;) {
      const queue=db.prepare("SELECT * FROM source_payload_queue WHERE state='pending' ORDER BY rowid LIMIT 1").get();
      if(!queue)break;
      const scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(queue.scan_task_id);
      const pipeline=scan && db.prepare('SELECT * FROM pipelines WHERE pipeline_id=? AND created_by IS ?').get(scan.pipeline_id,scan.created_by);
      if(!pipeline || !['COMPLETED','PARTIAL'].includes(scan.status)) {
        db.prepare("UPDATE source_payload_queue SET state='error',updated_at=CURRENT_TIMESTAMP WHERE scan_task_id=?").run(queue.scan_task_id);
        continue;
      }
      const rows=db.prepare("SELECT id FROM scan_results WHERE scan_task_id=? AND result_type='source_finding' AND id>? ORDER BY id").all(queue.scan_task_id,queue.last_finding_id);
      for(const row of rows) {
        let failed=false;
        try {
          const item=ensureVerification(db,pipeline,row.id);
          const previous=payloadArtifactView(db,item).collections[0];
          // Do not undo a manual stop or automatically repeat a known failed request.
          if(!previous || ['collecting','interrupted','uncertain'].includes(previous.state)) {
            startPayloadCollection(db,pipeline,item,{sub:pipeline.created_by,role:'user'},{},dependencies);
            await waitPayloadArtifacts(db,item);
          }
          failed=!['ready','empty','cancelled'].includes(payloadArtifactView(db,item).collections[0]?.state);
        } catch {failed=true;}
        db.prepare('UPDATE source_payload_queue SET last_finding_id=?,error_count=error_count+?,updated_at=CURRENT_TIMESTAMP WHERE scan_task_id=?')
          .run(row.id,failed?1:0,queue.scan_task_id);
      }
      db.prepare("UPDATE source_payload_queue SET state=CASE WHEN error_count>0 THEN 'partial' ELSE 'completed' END,updated_at=CURRENT_TIMESTAMP WHERE scan_task_id=?").run(queue.scan_task_id);
    }
  })().finally(()=>workers.delete(db));
  workers.set(db,work);return work;
}
