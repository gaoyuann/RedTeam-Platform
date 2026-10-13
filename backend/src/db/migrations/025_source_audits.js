export default function up(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS source_audits (
      scan_task_id TEXT PRIMARY KEY REFERENCES scan_tasks(scan_task_id) ON DELETE CASCADE,
      snapshot_id TEXT NOT NULL, connection_id TEXT NOT NULL,
      manifest TEXT NOT NULL, analysis TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS source_verifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      finding_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
      run_id TEXT NOT NULL REFERENCES execution_runs(run_id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK(status IN ('supported','not_reproduced','inconclusive')),
      evidence_ids TEXT NOT NULL, note TEXT NOT NULL, reviewed_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
  // Retain existing history, but retire the old static-tools-as-PoC template.
  const legacy=db.prepare("SELECT metadata FROM playbooks WHERE playbook_id='source_code_poc_verify'").get();
  if(legacy) {
    let metadata={};try {metadata=JSON.parse(legacy.metadata || '{}');} catch {}
    metadata.retired_source_template=true;
    db.prepare("UPDATE playbooks SET name=?,target_type=?,disable_auto_insert=1,metadata=? WHERE playbook_id='source_code_poc_verify'")
      .run('[已停用] 旧版源码静态扫描模板',JSON.stringify(['legacy_source_code']),JSON.stringify(metadata));
  }
}
