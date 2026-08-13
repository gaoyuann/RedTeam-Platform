/**
 * Migration 008: Add Rules Engine columns
 *
 * Adds columns for structured evidence storage and rule match tracking:
 * - evidence_records: structured_type, structured_data
 * - execution_steps: rule_matches
 */
export default function up(db) {
  // ── evidence_records: new columns ─────────────────────────────────────
  const evCols = db.prepare("PRAGMA table_info(evidence_records)").all()
    .map(c => c.name);

  if (!evCols.includes('structured_type')) {
    db.prepare("ALTER TABLE evidence_records ADD COLUMN structured_type TEXT").run();
    console.log('[Migration 008] Added evidence_records.structured_type');
  }

  if (!evCols.includes('structured_data')) {
    db.prepare("ALTER TABLE evidence_records ADD COLUMN structured_data TEXT").run();
    console.log('[Migration 008] Added evidence_records.structured_data');
  }

  // ── execution_steps: new column ───────────────────────────────────────
  const stepCols = db.prepare("PRAGMA table_info(execution_steps)").all()
    .map(c => c.name);

  if (!stepCols.includes('rule_matches')) {
    db.prepare("ALTER TABLE execution_steps ADD COLUMN rule_matches TEXT").run();
    console.log('[Migration 008] Added execution_steps.rule_matches');
  }
}
