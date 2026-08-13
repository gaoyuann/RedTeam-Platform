import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DEFAULT_SOURCE = resolve(
  __dirname, '..', '..', '..', '..', '..',
  'RedTeam-Edu', 'hexstrike-edu', 'backend', 'logs', 'classroom', 'db.json'
);

export default function up(db) {
  const sourcePath = process.env.CLASSROOM_DB_PATH || DEFAULT_SOURCE;
  let raw;
  try {
    raw = JSON.parse(readFileSync(sourcePath, 'utf-8'));
  } catch (err) {
    console.log(`[Migration 002] Source not found: ${sourcePath}, skipping`);
    return;
  }

  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (username, password, role, display_name)
    VALUES (?, ?, ?, ?)
  `);

  const insertClass = db.prepare(`
    INSERT OR IGNORE INTO classes (class_id, name, teacher_sub, join_code, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  const insertMembership = db.prepare(`
    INSERT OR IGNORE INTO memberships (class_id, user_sub, role, joined_at)
    VALUES (?, ?, ?, ?)
  `);

  const insertAssignment = db.prepare(`
    INSERT OR IGNORE INTO assignments (assignment_id, class_id, title, playbook_id, due_at, rubric, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertSubmission = db.prepare(`
    INSERT OR IGNORE INTO submissions (submission_id, assignment_id, class_id, student_sub, run_id, submitted_at, auto_grade, override_grade, final_grade, feedback, reviewed_at, reviewed_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const tx = db.transaction(() => {
    let count = 0;
    for (const u of raw.users || []) {
      insertUser.run(u.username, u.password, u.role, u.username);
      count++;
    }
    console.log(`[Migration 002] Imported ${count} users`);

    count = 0;
    for (const c of raw.classes || []) {
      insertClass.run(c.classId, c.name, c.teacherSub, c.joinCode, c.createdAt);
      count++;
    }
    console.log(`[Migration 002] Imported ${count} classes`);

    count = 0;
    for (const m of raw.memberships || []) {
      insertMembership.run(m.classId, m.userSub, m.role, m.joinedAt);
      count++;
    }
    console.log(`[Migration 002] Imported ${count} memberships`);

    count = 0;
    for (const a of raw.assignments || []) {
      insertAssignment.run(
        a.assignmentId, a.classId, a.title, a.playbookId, a.dueAt,
        a.rubric ? JSON.stringify(a.rubric) : null,
        a.createdBy, a.createdAt
      );
      count++;
    }
    console.log(`[Migration 002] Imported ${count} assignments`);

    count = 0;
    for (const s of raw.submissions || []) {
      insertSubmission.run(
        s.submissionId, s.assignmentId, s.classId, s.studentSub,
        s.runId, s.submittedAt,
        s.autoGrade ? JSON.stringify(s.autoGrade) : null,
        s.override ? JSON.stringify(s.override) : null,
        s.final ? JSON.stringify(s.final) : null,
        s.feedback || '',
        s.reviewedAt || null,
        s.reviewedBy || null
      );
      count++;
    }
    console.log(`[Migration 002] Imported ${count} submissions`);
  });

  tx();
}
