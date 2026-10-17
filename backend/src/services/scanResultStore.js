import { randomUUID } from 'node:crypto';
import { redactScanValue } from './scanResultCatalog.js';
export function hasScanIntegrity(db) {
  return Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_tool_runs'").get());
}
export function beginToolRun(db, scanTaskId, toolId, scanType) {
  if (!hasScanIntegrity(db)) return null; // legacy isolated fixtures/read-only old schema
  const id = randomUUID();
  db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at) VALUES (?,?,?,?,'running',?)")
    .run(id,scanTaskId,toolId,scanType,new Date().toISOString());
  return id;
}
export function finishToolRun(db, id, scanTaskId, toolId, result, parsed) {
  return db.transaction(() => {
    if (id && db.prepare('SELECT state FROM scan_tool_runs WHERE tool_run_id=?').get(id)?.state !== 'running') return 0;
    const insert = db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool,captured_at${id?',tool_run_id,record_index':''}) VALUES (?,?,?,?,?,?${id?',?,?':''})`);
    parsed.records.forEach((row,index) => insert.run(scanTaskId,row.result_type,
      JSON.stringify(redactScanValue(row.result_data)),row.severity || null,row.source_tool || toolId,new Date().toISOString(),...(id?[id,index]:[])));
    if (id) {
      const state=result.aborted?'cancelled':result.timedOut?'timed_out':result.success?'completed':'failed';
      const outcome={exit_code:result.exitCode ?? null,timed_out:!!result.timedOut,aborted:!!result.aborted,
        output_limit_exceeded:!!result.outputLimitExceeded,error:result.error || null,
        incomplete:!result.success || !!parsed.diagnostics.unparsed_lines || !!parsed.diagnostics.evidence_truncated,
        parser_coverage_known:parsed.diagnostics.unparsed_lines !== null && parsed.diagnostics.unparsed_lines !== undefined,
        stopped:result.processStopped !== false};
      db.prepare('UPDATE scan_tool_runs SET state=?,completed_at=?,outcome=?,diagnostics=?,evidence=? WHERE tool_run_id=?')
        .run(state,new Date().toISOString(),JSON.stringify(redactScanValue(outcome)),
          JSON.stringify({...parsed.diagnostics,persisted_records:parsed.records.length}),
          JSON.stringify(redactScanValue({stdout:result.stdout || '',stderr:result.stderr || '',
            truncated:!!result.outputLimitExceeded,bytes_observed:result.outputBytes ?? null,execution_mode:result.executionMode || null})),id);
    }
    return parsed.records.length;
  })();
}
