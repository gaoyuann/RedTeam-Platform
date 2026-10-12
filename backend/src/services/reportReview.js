import { currentActor } from '../middleware/recordAccess.js';
import { appendTaskLog, sanitizeTaskLog } from './taskActivity.js';

const notice = '审阅只确认此冻结报告的材料与表述，不代表漏洞已验证、目标安全或报告已发布；候选复核状态保持不变。';
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };

export function reportReview(db, reportId, fingerprint) {
  const available = !!db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='task_report_reviews'").get();
  const summary = { available, state: 'draft', revision: 0, source_fingerprint: fingerprint, submitted_by: null,
    updated_at: null, history: [], history_total: 0, history_limit: 20, notice };
  if (!available) return summary;
  const rows = db.prepare('SELECT * FROM task_report_reviews WHERE report_id = ? ORDER BY revision DESC LIMIT 20').all(reportId);
  if (!rows.length) return summary;
  const latest = rows[0];
  summary.state = latest.source_fingerprint === fingerprint ? latest.state : 'invalid';
  summary.revision = latest.revision;
  summary.updated_at = latest.created_at;
  summary.submitted_by = db.prepare("SELECT actor FROM task_report_reviews WHERE report_id = ? AND action = 'submit' ORDER BY revision DESC LIMIT 1").get(reportId)?.actor || null;
  summary.history_total = db.prepare('SELECT COUNT(*) AS count FROM task_report_reviews WHERE report_id = ?').get(reportId).count;
  summary.history = rows.reverse().map(row => ({ revision: row.revision, action: row.action, from_state: row.from_state,
    state: row.state, actor: row.actor, actor_role: row.actor_role, note: sanitizeTaskLog(row.note), created_at: row.created_at }));
  return summary;
}

export function transitionReportReview(db, pipeline, document, actor, body) {
  if (!currentActor(db, actor)) fail(401, '登录身份已失效，请重新登录');
  if (actor.role !== 'admin' && actor.sub !== pipeline.created_by) fail(403, '没有权限审阅此任务报告');
  const report = document.report;
  if (report.kind !== 'trace_snapshot') fail(409, '历史报告缺少冻结来源，不能使用新式审阅流程');
  if (!body || typeof body !== 'object' || Array.isArray(body) || !['submit', 'approve', 'reject', 'reopen'].includes(body.action)
      || !Number.isSafeInteger(body.revision) || body.revision < 0 || body.source_fingerprint !== report.source_fingerprint
      || typeof body.note !== 'string' || !body.note.trim() || body.note.length > 1000 || body.acknowledged !== true)
    fail(400, '审阅参数无效：请确认版本、冻结来源、审阅说明和范围声明');
  const review = reportReview(db, report.report_id, report.source_fingerprint);
  if (!review.available) fail(503, '审阅迁移尚未就绪，请更新后端');
  if (review.state === 'invalid' || review.revision !== body.revision) fail(409, '审阅状态或冻结来源已变化，请刷新后重新确认');
  let nextState;
  if (body.action === 'submit') {
    if (!['draft', 'rejected'].includes(review.state)) fail(409, '仅草稿或退回报告可以提审');
    nextState = 'submitted';
  } else {
    if (actor.role !== 'admin') fail(403, '审核和重新打开仅限管理员');
    if (body.action === 'reopen') {
      if (review.state !== 'reviewed') fail(409, '仅已审阅报告可以重新打开');
      nextState = 'draft';
    } else {
      if (review.state !== 'submitted') fail(409, '仅待审报告可以通过或退回');
      if (actor.sub === pipeline.created_by || actor.sub === review.submitted_by) fail(403, '审核人不能是任务所有者或本轮提交人');
      nextState = body.action === 'approve' ? 'reviewed' : 'rejected';
    }
  }
  const timestamp = new Date().toISOString();
  const note = sanitizeTaskLog(body.note.trim());
  if (!note.trim()) fail(400, '审阅说明不能仅包含控制字符');
  db.prepare(`INSERT INTO task_report_reviews (report_id,pipeline_id,revision,source_fingerprint,action,from_state,state,actor,actor_role,note,created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(report.report_id, pipeline.pipeline_id, review.revision + 1,
      report.source_fingerprint, body.action, review.state, nextState, actor.sub, actor.role, note, timestamp);
  db.prepare(`INSERT INTO audit_log (type,execution_id,run_id,user_role,target,reasons,timestamp)
    VALUES ('task_report_review', ?, ?, ?, ?, ?, ?)`).run(report.report_id, report.run_id, actor.role, document.target,
      JSON.stringify({ pipeline_id: pipeline.pipeline_id, actor: actor.sub, action: body.action, revision: review.revision + 1,
        from: review.state, to: nextState, source_fingerprint: report.source_fingerprint, note }), timestamp);
  appendTaskLog(db, pipeline.pipeline_id, `报告审阅 · ${report.report_id} · ${body.action} · 版本 ${review.revision + 1}`);
  return { pipeline_id: pipeline.pipeline_id, report_id: report.report_id, review: reportReview(db, report.report_id, report.source_fingerprint) };
}
