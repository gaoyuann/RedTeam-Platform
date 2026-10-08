export function getReportAssessment(db, run, steps) {
  let summary = {};
  try { summary = JSON.parse(run.final_summary || '{}') || {}; } catch {}
  const attempted = db.prepare('SELECT COUNT(*) AS count FROM execution_attempts WHERE run_id = ?').get(run.run_id).count;
  const succeeded = steps.filter(step => step.success === 1 && step.exit_code === 0).length;
  const failed = steps.length - succeeded;
  const planned = db.prepare('SELECT COUNT(*) AS count FROM playbook_steps WHERE playbook_id = ?').get(run.playbook_id || '').count;
  const total = Number.isFinite(summary.total) ? Math.max(summary.total, steps.length) : Math.max(planned, steps.length);
  const unexecuted = Number.isFinite(summary.unexecuted) ? summary.unexecuted : Math.max(0, total - steps.length);
  const stopReason = run.stop_reason || summary.stopReason || summary.error ||
    (summary.preflightFailed ? summary.preflightFailed.join('; ') : '未记录');
  return {
    status: run.status,
    total, executed: steps.length, succeeded, failed, unexecuted,
    attempts: attempted || summary.attempts || steps.length,
    stopReason,
    riskLevel: '未评级（需人工复核证据）',
    executionText: `计划 ${total} 步，已执行 ${steps.length} 步，成功 ${succeeded} 步，失败 ${failed} 步，未执行 ${unexecuted} 步；执行尝试 ${attempted || summary.attempts || steps.length} 次。`,
    notice: '教学得分仅反映执行与证据覆盖，不代表目标风险评级。工具成功退出不等于漏洞利用成功；自动提取发现需人工确认，失败或未执行项不得视为安全。历史记录保留原始状态，未按新逻辑回写。',
  };
}

export function formatMitreHits(value) {
  try {
    const hits = Array.isArray(value) ? value : JSON.parse(value || '[]');
    if (!Array.isArray(hits)) return '';
    return [...new Set(hits.map(hit => typeof hit === 'string' ? hit : hit?.id).filter(Boolean))].join(', ');
  } catch {
    return '';
  }
}
