export function createStepIndexAllocator(steps) {
  let nextIndex = Math.max(-1, ...steps.map(step => step.step_index)) + 1;
  return () => nextIndex++;
}

export function buildExecutionSummary({ steps, manualAbort, timeoutAbort, reactStopped, stopReason, engineType, reactCallCount, attempts }) {
  const completed = steps.filter(step => step.execution_finished && step.execution_success).length;
  const failed = steps.filter(step => step.execution_finished && !step.execution_success).length;
  const unexecuted = steps.filter(step => !step.execution_finished).length;
  const requiredIncomplete = steps.some(step => !step.optional && (!step.execution_finished || !step.execution_success));
  const status = manualAbort ? 'ABORTED' : timeoutAbort ? 'FAILED' : 'COMPLETED';
  const error = status === 'FAILED' ? stopReason || '运行超时' : null;
  return { status, error, summary: {
    total: steps.length, completed, failed, unexecuted, attempts,
    aborted: manualAbort, reactStopped, timeoutAbort, hasNonOptionalFailure: requiredIncomplete,
    stopReason, error, engineType, reactCallCount, completionPolicy: 'execution_finished',
  } };
}
