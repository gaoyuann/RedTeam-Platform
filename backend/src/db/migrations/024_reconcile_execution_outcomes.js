function parseObject(value) {
  try {
    const parsed = JSON.parse(value || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch { return null; }
}

export default function up(db) {
  db.transaction(() => {
    const runs = db.prepare("SELECT run_id, final_summary FROM execution_runs WHERE status = 'COMPLETED'").all();
    const timestamp = new Date().toISOString();
    for (const run of runs) {
      const summary = parseObject(run.final_summary);
      if (!summary) continue;
      const failed = Number.isSafeInteger(summary.failed) && summary.failed > 0;
      const unexecuted = Number.isSafeInteger(summary.unexecuted) && summary.unexecuted > 0;
      if (!failed && !unexecuted && summary.hasNonOptionalFailure !== true && summary.timeoutAbort !== true) continue;
      const error = [summary.stopReason, summary.error].find(value => typeof value === 'string' && value.trim())
        || '执行摘要包含失败或未执行步骤，不能视为完整完成';
      const repaired = JSON.stringify({ ...summary, error, completionPolicy: 'all_steps_succeeded',
        statusReconciliation: { previousStatus: 'COMPLETED', timestamp } });
      db.prepare("UPDATE execution_runs SET status = 'FAILED', final_summary = ?, score_data = NULL, updated_at = ? WHERE run_id = ?")
        .run(repaired, timestamp, run.run_id);
      const pipelines = db.prepare("SELECT pipeline_id, result FROM pipelines WHERE run_id = ? AND status = 'completed'").all(run.run_id);
      for (const pipeline of pipelines) {
        const result = parseObject(pipeline.result) || {};
        const execution = result.execution && typeof result.execution === 'object' && !Array.isArray(result.execution)
          ? result.execution : {};
        result.execution = { ...execution, run_id: run.run_id, status: 'FAILED' };
        result.statusReconciliation = { previousStatus: 'completed', timestamp };
        db.prepare("UPDATE pipelines SET status = 'failed', result = ?, error_message = ?, updated_at = ? WHERE pipeline_id = ?")
          .run(JSON.stringify(result), `执行阶段未完整完成：${error}`, timestamp, pipeline.pipeline_id);
        const steps = db.prepare("SELECT id, output_data FROM pipeline_steps WHERE pipeline_id = ? AND step_type = 'execute' AND status = 'completed'")
          .all(pipeline.pipeline_id);
        for (const step of steps) {
          const output = parseObject(step.output_data) || {};
          db.prepare("UPDATE pipeline_steps SET status = 'failed', output_data = ?, error_message = ? WHERE id = ?")
            .run(JSON.stringify({ ...output, run_id: run.run_id, status: 'FAILED', final_summary: repaired }), error, step.id);
        }
      }
    }
  })();
}
