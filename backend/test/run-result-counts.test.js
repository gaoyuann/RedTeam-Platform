import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeRunResultCounts } from '../src/services/runResultCounts.js';

test('zero-valued step outcomes are returned failures rather than missing results', () => {
  const counts = summarizeRunResultCounts([
    { id: 10, step_index: 0, success: 0 },
    { id: 11, step_index: 1, success: 0 },
  ], 'COMPLETED');
  assert.deepEqual(counts, {
    records: 2, known: 2, returned: 2, succeeded: 0, failed: 2, pending: 0,
    duplicate_records: 0, count_consistent: true, terminal_pending: false, requires_attention: false,
  });
});

test('unfinished step records remain visible and are flagged after terminal completion', () => {
  const counts = summarizeRunResultCounts([
    { id: 20, step_index: 0, success: null },
    { id: 21, step_index: 1, success: undefined },
  ], 'COMPLETED');
  assert.equal(counts.known, 2);
  assert.equal(counts.returned, 0);
  assert.equal(counts.succeeded, 0);
  assert.equal(counts.failed, 0);
  assert.equal(counts.pending, 2);
  assert.equal(counts.count_consistent, true);
  assert.equal(counts.terminal_pending, true);
  assert.equal(counts.requires_attention, true);
});

test('planned steps without records are pending and flagged after a terminal run', () => {
  const counts = summarizeRunResultCounts([{ id: 25, step_index: 0, success: true }], 'COMPLETED', { knownStepCount: 2 });
  assert.equal(counts.known, 2);
  assert.equal(counts.returned, 1);
  assert.equal(counts.succeeded, 1);
  assert.equal(counts.failed, 0);
  assert.equal(counts.pending, 1);
  assert.equal(counts.terminal_pending, true);
});

test('latest duplicate step record wins while the duplicate is reported', () => {
  const counts = summarizeRunResultCounts([
    { id: 30, step_index: 0, success: false },
    { id: 31, step_index: 0, success: true },
    { id: 32, step_index: 1, success: null },
  ], 'RUNNING');
  assert.equal(counts.records, 3);
  assert.equal(counts.known, 2);
  assert.equal(counts.returned, 1);
  assert.equal(counts.succeeded, 1);
  assert.equal(counts.failed, 0);
  assert.equal(counts.pending, 1);
  assert.equal(counts.duplicate_records, 1);
  assert.equal(counts.terminal_pending, false);
  assert.equal(counts.requires_attention, true);
});
