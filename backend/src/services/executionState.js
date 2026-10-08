export function createStepIndexAllocator(steps) {
  let nextIndex = Math.max(-1, ...steps.map(step => step.step_index)) + 1;
  return () => nextIndex++;
}

export function buildExecutionSummary({ steps, completed, failed, manualAbort, timeoutAbort, reactStopped, stopReason, engineType, reactCallCount, attempts }) {
  const unexecuted = steps.filter(step => !step.execution_finished).length;
  const requiredIncomplete = steps.some(step => !step.optional && (!step.execution_finished || !step.execution_success));
  const status = manualAbort ? 'ABORTED' : timeoutAbort || requiredIncomplete ? 'FAILED' : 'COMPLETED';
  return { status, summary: {
    total: steps.length, completed, failed, unexecuted, attempts,
    aborted: manualAbort, reactStopped, timeoutAbort, hasNonOptionalFailure: requiredIncomplete,
    stopReason, engineType, reactCallCount,
  } };
}
