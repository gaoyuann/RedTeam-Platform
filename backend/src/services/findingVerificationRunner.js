import { assessVerificationAttempt } from './findingVerificationAssessment.js';
import { taskDisplayValue } from './taskExecution.js';
import { checkVerificationPlan, json } from './findingVerification.js';
import { currentActor } from '../middleware/recordAccess.js';
import { broadcastTaskEvent } from './taskActivity.js';

// One server process owns an attempt. Unknown attempts are never replayed after restart.
const workers = new Map();
export function attemptIsLive(id) { return workers.has(id); }
export function reconcileVerificationAttempts(db, pipelineId) {
  const rows=db.prepare("SELECT * FROM finding_verification_attempts WHERE pipeline_id=? AND state IN ('queued','running','cancelling')").all(pipelineId);
  for(const row of rows) if(!workers.has(row.id)) {
    db.prepare("UPDATE finding_verification_attempts SET state='unknown',reason='服务重启或执行句柄丢失，需核实调用停止；不会自动重放' WHERE id=?").run(row.id);
    db.prepare("UPDATE finding_verifications SET state='unknown',reason='实际停止状态未确认，请核查执行环境' WHERE id=?").run(row.verification_id);
  }
}
export function launchVerification(db, attempt, actor, dependencies = {}) {
  if(attempt.reused || workers.has(attempt.id)) return;
  const marker={cancelled:false}; workers.set(attempt.id,marker);
  const task=async()=>{
    let result, engine, enteredEngine=false;
    try {
      engine=dependencies.engine || await import('./executionEngine.js');
      const pipeline=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(attempt.pipeline_id);
      const record=currentActor(db,actor);
      const fresh=record ? {...record,sub:record.username} : null;
      if(!fresh || (fresh.role!=='admin' && fresh.sub!==pipeline?.created_by)) throw new Error('任务权限已失效');
      checkVerificationPlan(db,pipeline,fresh,attempt.verification_id,attempt.revision);
      if(marker.cancelled) {
        db.prepare("UPDATE execution_runs SET status='ABORTED',stop_reason='启动前取消' WHERE run_id=?").run(attempt.run_id);
        result={status:'ABORTED',processStopped:true};
      } else {
        db.prepare("UPDATE finding_verification_attempts SET state='running' WHERE id=?").run(attempt.id);
        db.prepare("UPDATE finding_verifications SET state='running' WHERE id=?").run(attempt.verification_id);
        enteredEngine=true;
        result=await engine.executeRun(attempt.run_id);
      }
    } catch {
      // Do not publish raw runtime/model errors which may contain sensitive arguments.
      result={status:'FAILED',processStopped:!enteredEngine,error:'验证启动或执行异常，请查看脱敏执行证据'};
      db.prepare("UPDATE execution_runs SET status='FAILED',stop_reason=? WHERE run_id=? AND status IN ('PENDING','RUNNING')")
        .run(result.error,attempt.run_id);
    } finally {
      const run=db.prepare('SELECT status,stop_reason,final_summary FROM execution_runs WHERE run_id=?').get(attempt.run_id);
      // Engine records actual stop acknowledgement; a status label alone is insufficient.
      const stopped=result?.processStopped === true || json(run?.final_summary).verification_stop_confirmed === true;
      const expected=db.prepare('SELECT count(*) n FROM playbook_steps WHERE playbook_id=(SELECT playbook_id FROM execution_runs WHERE run_id=?)').get(attempt.run_id).n;
      const actual=db.prepare('SELECT step_index,success FROM execution_steps WHERE run_id=? ORDER BY id').all(attempt.run_id);
      const latest=new Map(actual.map(s=>[s.step_index,s.success]));
      const successful=latest.size===expected && expected>0 && [...latest.values()].every(v=>v===1);
      const state=!stopped ? 'unknown' : run?.status==='ABORTED' ? 'aborted' : run?.status==='COMPLETED' && successful ? 'completed' : 'failed';
      const reason=!stopped ? '实际调用停止尚未确认，禁止重试和恢复环境' : taskDisplayValue(result?.error || (state==='failed' ? '步骤异常、未执行或预检失败；请查看证据' : null));
      db.transaction(()=>{
        if(!enteredEngine)db.prepare('UPDATE execution_runs SET final_summary=? WHERE run_id=?')
          .run(JSON.stringify({...json(run?.final_summary),verification_dispatch_started:false}),attempt.run_id);
        db.prepare("UPDATE finding_verification_attempts SET state=?,stop_confirmed=?,reason=?,completed_at=datetime('now') WHERE id=?")
          .run(state,stopped?1:0,reason,attempt.id);
        db.prepare('UPDATE finding_verifications SET state=?,reason=? WHERE id=?').run(state,reason,attempt.verification_id);
      })();
      assessVerificationAttempt(db,attempt.id);
      workers.delete(attempt.id);
      broadcastTaskEvent(db,'pipeline:verification',{pipeline_id:attempt.pipeline_id,verification_id:attempt.verification_id,state});
    }
  };
  marker.promise=Promise.resolve().then(task);
  return marker.promise;
}
export async function cancelVerification(db, attempt, dependencies={}) {
  const marker=workers.get(attempt.id);
  if(!marker) {reconcileVerificationAttempts(db,attempt.pipeline_id);return;}
  marker.cancelled=true;
  db.prepare("UPDATE finding_verification_attempts SET state='cancelling' WHERE id=?").run(attempt.id);
  db.prepare("UPDATE finding_verifications SET state='cancelling' WHERE id=?").run(attempt.verification_id);
  const engine=dependencies.engine || await import('./executionEngine.js');
  if(workers.has(attempt.id)) engine.requestAbort(attempt.run_id);
}
