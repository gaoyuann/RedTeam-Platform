export default function up(db) {
  if(!db.prepare('PRAGMA table_info(task_entries)').all().some(c=>c.name==='metadata'))
    db.exec("ALTER TABLE task_entries ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'");
}
