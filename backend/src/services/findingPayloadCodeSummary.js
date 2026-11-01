// Read only metadata for the current task's findings. Keep the same 5 collection /
// 20 generation windows as the payload detail page, without returning source code.
export function findingPayloadCodeSummaries(db, pipelineId, findingIds) {
  const summaries = new Map();
  if (!findingIds.length) return summaries;
  const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('finding_verifications','finding_payload_collections','finding_verification_code')").all().map(row => row.name));
  const supported = tables.size === 3;
  for (const id of findingIds) summaries.set(id, {
    schema_version: 1, state: supported ? 'missing' : 'unavailable',
    scan_count: supported ? 0 : null, generated_count: supported ? 0 : null,
    latest_generation_state: null,
  });
  if (!supported) return summaries;
  const placeholders = findingIds.map(() => '?').join(',');
  const rows = (table, column, path, contentKey, limit) => db.prepare(`
    WITH recent AS (
      SELECT v.finding_id, p.state, p.${column} AS content,
        ROW_NUMBER() OVER (PARTITION BY v.id ORDER BY p.rowid DESC) AS position
      FROM finding_verifications v JOIN ${table} p ON p.verification_id=v.id
      WHERE v.pipeline_id=? AND v.finding_id IN (${placeholders})
    )
    SELECT finding_id, state, position,
      (SELECT count(*) FROM json_each(CASE WHEN json_valid(content) THEN
          CASE WHEN json_type(content, '${path}')='array' THEN json_extract(content, '${path}') ELSE '[]' END ELSE '[]' END)
        WHERE type='object' AND typeof(json_extract(value, '$.${contentKey}'))='text'
          AND length(trim(json_extract(value, '$.${contentKey}')))>0) AS file_count
    FROM recent WHERE position<=? ORDER BY position
  `).all(pipelineId, ...findingIds, limit);
  for (const row of rows('finding_payload_collections', 'scripts', '$', 'content', 5)) {
    const summary = summaries.get(row.finding_id);
    if (!summary.scan_count && row.state === 'ready' && row.file_count) summary.scan_count = row.file_count;
  }
  for (const row of rows('finding_verification_code', 'result', '$.files', 'source', 20)) {
    const summary = summaries.get(row.finding_id);
    if (row.position === 1) summary.latest_generation_state = row.state;
    if (!summary.generated_count && row.state === 'ready' && row.file_count) summary.generated_count = row.file_count;
  }
  for (const summary of summaries.values()) {
    summary.state = summary.scan_count + summary.generated_count > 0 ? 'available'
      : ['generating', 'needs_information', 'error', 'interrupted'].includes(summary.latest_generation_state)
        ? summary.latest_generation_state : 'missing';
  }
  return summaries;
}
