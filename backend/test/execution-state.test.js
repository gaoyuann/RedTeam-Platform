import test from 'node:test';
import assert from 'node:assert/strict';
import { buildExecutionSummary, createStepIndexAllocator } from '../src/services/executionState.js';

function summarize(steps, overrides = {}) {
  return buildExecutionSummary({
    steps, manualAbort: false, timeoutAbort: false, reactStopped: false,
    stopReason: null, engineType: 'react', reactCallCount: 0, attempts: steps.length,
    ...overrides,
  });
}

function step(stepIndex, success, optional = false) {
  return {
    step_index: stepIndex, optional,
    execution_finished: success !== undefined, execution_success: success === true,
  };
}

test('all successful steps finish without grading the execution status', () => {
  const result = summarize([step(0, true), step(1, true)]);
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.error, null);
  assert.equal(result.summary.completed, 2);
  assert.equal(result.summary.failed, 0);
  assert.equal(result.summary.completionPolicy, 'execution_finished');
});

test('required step failures remain recorded without failing normal completion', () => {
  const result = summarize([step(0, true), step(1, false)]);
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.error, null);
  assert.equal(result.summary.error, null);
  assert.equal(result.summary.completed, 1);
  assert.equal(result.summary.failed, 1);
  assert.equal(result.summary.hasNonOptionalFailure, true);
});

test('failed AI extensions do not fail execution or alter original step results', () => {
  const steps = Array.from({ length: 17 }, (_, index) => step(index, index < 15, index >= 10));
  const original = structuredClone(steps);
  const result = summarize(steps);
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.summary.total, 17);
  assert.equal(result.summary.completed, 15);
  assert.equal(result.summary.failed, 2);
  assert.equal(result.summary.unexecuted, 0);
  assert.equal(result.summary.hasNonOptionalFailure, false);
  assert.deepEqual(steps, original);
});

test('an execution with no successful tools still completes for scoring', () => {
  const result = summarize([step(0, false), step(1, false)]);
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.summary.completed, 0);
  assert.equal(result.summary.failed, 2);
});

test('AI termination keeps unexecuted steps and the reason available for assessment', () => {
  const reason = 'No remaining useful actions';
  const result = summarize([step(0, true), step(1, undefined)], { reactStopped: true, stopReason: reason });
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.error, null);
  assert.equal(result.summary.unexecuted, 1);
  assert.equal(result.summary.hasNonOptionalFailure, true);
  assert.equal(result.summary.reactStopped, true);
  assert.equal(result.summary.stopReason, reason);
});

test('counts reflect final step outcomes instead of stale retry counters', () => {
  const result = summarize([step(0, true), step(1, false), step(2, undefined)], {
    completed: 8, failed: 5, attempts: 13,
  });
  assert.equal(result.summary.completed, 1);
  assert.equal(result.summary.failed, 1);
  assert.equal(result.summary.unexecuted, 1);
  assert.equal(result.summary.attempts, 13);
});

test('manual abort remains aborted rather than claiming normal completion', () => {
  const result = summarize([step(0, true), step(1, undefined)], {
    manualAbort: true, stopReason: '操作员手动中止',
  });
  assert.equal(result.status, 'ABORTED');
  assert.equal(result.summary.aborted, true);
  assert.equal(result.summary.unexecuted, 1);
});

test('execution deadline remains a runtime failure with its diagnostic', () => {
  const result = summarize([step(0, false), step(1, undefined)], {
    timeoutAbort: true, stopReason: '运行超时',
  });
  assert.equal(result.status, 'FAILED');
  assert.equal(result.error, '运行超时');
  assert.equal(result.summary.timeoutAbort, true);
  assert.equal(result.summary.failed, 1);
  assert.equal(result.summary.unexecuted, 1);
});

test('manual abort takes precedence over an execution deadline', () => {
  const result = summarize([step(0, undefined)], { manualAbort: true, timeoutAbort: true });
  assert.equal(result.status, 'ABORTED');
});

test('step index allocation remains unique after inserted steps', () => {
  const allocate = createStepIndexAllocator([step(0, true), step(15, false, true)]);
  assert.equal(allocate(), 16);
  assert.equal(allocate(), 17);
});
