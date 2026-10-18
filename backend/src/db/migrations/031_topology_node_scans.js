export default function up(db) {
  db.transaction(() => {
    const columns = db.prepare('PRAGMA table_info(scan_tasks)').all();
    if (!columns.some(column => column.name === 'topology_request_id'))
      db.exec('ALTER TABLE scan_tasks ADD COLUMN topology_request_id TEXT');
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_node_request
      ON scan_tasks(pipeline_id, topology_request_id)
      WHERE pipeline_id IS NOT NULL AND topology_request_id IS NOT NULL`);
  })();
}
