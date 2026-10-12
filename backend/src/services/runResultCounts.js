function outcomeState(value) {
  if (value === true || value === 1) return 'succeeded';
  if (value === false || value === 0) return 'failed';
  return 'pending';
}

function isTerminalStatus(status) {
  return ['COMPLETED', 'FAILED', 'ABORTED'].includes(String(status || '').toUpperCase());
}

export function summarizeRunResultCounts(steps, status, { knownStepCount = 0 } = {}) {
  const records = Array.isArray(steps) ? steps : [];
  const latestByStep = new Map();
  records.forEach((step, position) => {
    const key = Number.isInteger(step?.step_index)
      ? `step:${step.step_index}`
      : `record:${step?.id ?? position}`;
    latestByStep.set(key, step);
  });

  const latest = [...latestByStep.values()];
  const configuredKnownCount = Number.isSafeInteger(knownStepCount) && knownStepCount > 0 ? knownStepCount : 0;
  const known = Math.max(latest.length, configuredKnownCount);
  const succeeded = latest.filter(step => outcomeState(step?.success) === 'succeeded').length;
  const failed = latest.filter(step => outcomeState(step?.success) === 'failed').length;
  const pending = known - succeeded - failed;
  const returned = succeeded + failed;
  const terminalPending = isTerminalStatus(status) && pending > 0;

  return {
    records: records.length,
    known,
    returned,
    succeeded,
    failed,
    pending,
    duplicate_records: records.length - latest.length,
    count_consistent: returned + pending === known,
    terminal_pending: terminalPending,
    requires_attention: terminalPending || records.length !== latest.length,
  };
}
