import { builtinVerificationPlans } from '../../services/findingVerificationRules.js';

export default function up(db) {
  db.transaction(() => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS finding_payload_events (
        id INTEGER PRIMARY KEY, verification_id TEXT NOT NULL REFERENCES finding_verifications(id),
        action TEXT NOT NULL CHECK(action IN ('generated','reused','bound','unbound')),
        payload_id TEXT NOT NULL, payload_version TEXT NOT NULL, revision INTEGER,
        step_id TEXT, actor TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_finding_payload_events ON finding_payload_events(verification_id,id);
      CREATE TABLE IF NOT EXISTS finding_verification_assessments (
        id INTEGER PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES finding_verification_attempts(id),
        rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL,
        conclusion TEXT NOT NULL, evidence_ids TEXT NOT NULL, reason TEXT NOT NULL, limitations TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(attempt_id,rule_id,rule_version)
      );
    `);
    for (const plan of builtinVerificationPlans) {
      db.prepare(`INSERT OR IGNORE INTO playbooks(playbook_id,name,description,target_type,metadata,is_generated,disable_auto_insert,roles_allowed)
        VALUES(?,?,?,'["web_url","local_ip"]',?,0,1,'["admin","user"]')`)
        .run(plan.id,plan.name,plan.description,JSON.stringify({finding_template:plan}));
      db.prepare(`INSERT OR IGNORE INTO playbook_steps(playbook_id,step_index,step_id,name,tool_id,args_template,description,evidence_config,optional)
        VALUES(?,0,'observe','请求指定入口','target-request',?,'只读请求，保留响应证据',?,0)`)
        .run(plan.id,JSON.stringify([JSON.stringify({url:'<target>',method:'GET',timeout_ms:10000})]),
          JSON.stringify({expected_evidence:plan.expected_evidence}));
    }
  })();
}
