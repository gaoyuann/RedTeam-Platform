/**
 * Migration 006: Add ReAct engine columns
 *
 * Adds columns to support the ReAct (Reasoning + Acting) execution engine:
 * - execution_runs: engine_type, evidence_history, react_thoughts
 * - execution_steps: react_thought, react_action
 */
export default function up(db) {
  // ── execution_runs: new columns ──────────────────────────────────────
  const runCols = db.prepare("PRAGMA table_info(execution_runs)").all()
    .map(c => c.name);

  if (!runCols.includes('engine_type')) {
    db.prepare("ALTER TABLE execution_runs ADD COLUMN engine_type TEXT DEFAULT 'mechanical'").run();
    console.log('[Migration 006] Added execution_runs.engine_type');
  }

  if (!runCols.includes('evidence_history')) {
    db.prepare("ALTER TABLE execution_runs ADD COLUMN evidence_history TEXT").run();
    console.log('[Migration 006] Added execution_runs.evidence_history');
  }

  if (!runCols.includes('react_thoughts')) {
    db.prepare("ALTER TABLE execution_runs ADD COLUMN react_thoughts TEXT").run();
    console.log('[Migration 006] Added execution_runs.react_thoughts');
  }

  // ── execution_steps: new columns ─────────────────────────────────────
  const stepCols = db.prepare("PRAGMA table_info(execution_steps)").all()
    .map(c => c.name);

  if (!stepCols.includes('react_thought')) {
    db.prepare("ALTER TABLE execution_steps ADD COLUMN react_thought TEXT").run();
    console.log('[Migration 006] Added execution_steps.react_thought');
  }

  if (!stepCols.includes('react_action')) {
    db.prepare("ALTER TABLE execution_steps ADD COLUMN react_action TEXT").run();
    console.log('[Migration 006] Added execution_steps.react_action');
  }
}
