import { randomUUID } from 'crypto';
import { isDeepStrictEqual } from 'node:util';
import { parseVariableContract } from './executionVariables.js';
import { appendTaskLog } from './taskActivity.js';
import { assertPlaybookUse } from './playbookAccess.js';

function fail(status, message) {
  throw Object.assign(new Error(message), { status });
}

function json(value, fallback) {
  if (value === null || value === undefined || value === '') return fallback;
  try { return typeof value === 'string' ? JSON.parse(value) : value; }
  catch { fail(400, '预案中的 JSON 格式无效'); }
}

function text(value, limit, field) {
  if (typeof value !== 'string' || value.length > limit) fail(400, `${field}格式错误或超出长度限制`);
  return value;
}

function args(value) {
  const parsed = json(value, []);
  if (!Array.isArray(parsed) || parsed.length > 200 || parsed.some(arg => typeof arg !== 'string' || arg.length > 4000))
    fail(400, '步骤参数必须是 JSON 字符串数组（最多 200 项）');
  return parsed;
}

export function getTaskPlan(db, pipelineId) {
  const row = db.prepare('SELECT * FROM task_plans WHERE pipeline_id = ?').get(pipelineId);
  if (!row) return null;
  return {
    ...row,
    content: JSON.parse(row.content),
    history: db.prepare(`SELECT id, revision, action, actor, actor_role, note, created_at
      FROM task_plan_history WHERE pipeline_id = ? ORDER BY id DESC LIMIT 50`).all(pipelineId),
  };
}

function record(db, pipelineId, actor, action, note = '') {
  const row = db.prepare('SELECT * FROM task_plans WHERE pipeline_id = ?').get(pipelineId);
  db.prepare(`INSERT INTO task_plan_history (pipeline_id, revision, action, actor, actor_role, note, snapshot)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(pipelineId, row.revision, action, actor.sub, actor.role, note, row.content);
  const pipeline = db.prepare('SELECT target FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
  db.prepare(`INSERT INTO audit_log (type, execution_id, user_role, target, reasons, timestamp)
    VALUES (?, ?, ?, ?, ?, datetime('now'))`).run(`task_plan_${action}`, pipelineId, actor.role, pipeline.target,
      JSON.stringify({ actor: actor.sub, revision: row.revision, state: row.state }));
  const labels = { create: '建立预案草稿', save: '保存预案编辑', add_suggestion: '加入分析候选',
    submit: '提交预案审批', reopen: '预案返回编辑', reject: '预案审批驳回', approve: '批准预案并请求执行' };
  appendTaskLog(db, pipelineId, `${labels[action] || action} · 记录版本 v${row.revision}`, action === 'reject' ? 'warn' : 'info');
}

function waiting(pipeline) {
  if (pipeline.status !== 'awaiting_approval') fail(409, '只有待审批任务可以修改或审批预案');
}

function checkedPlan(db, pipeline, revision, states) {
  waiting(pipeline);
  const plan = getTaskPlan(db, pipeline.pipeline_id);
  if (!plan) fail(404, '请先从已有预案建立任务草稿');
  if (!Number.isInteger(revision) || revision !== plan.revision) fail(409, '预案版本已变化，请刷新后重新审阅');
  if (!states.includes(plan.state)) fail(409, '当前预案状态不允许此操作');
  return plan;
}

function update(db, pipelineId, actor, action, state, content, note = '') {
  db.prepare(`UPDATE task_plans SET state = ?, revision = revision + 1, content = ?, updated_at = datetime('now')
    WHERE pipeline_id = ?`).run(state, JSON.stringify(content), pipelineId);
  record(db, pipelineId, actor, action, note);
  return getTaskPlan(db, pipelineId);
}

export function createTaskPlan(db, pipeline, actor, playbookId) {
  waiting(pipeline);
  if (getTaskPlan(db, pipeline.pipeline_id)) fail(409, '任务已有草稿，请刷新，不要重复初始化');
  const sourceId = playbookId || pipeline.generated_playbook_id;
  assertPlaybookUse(db, sourceId, actor, pipeline.created_by);
  const playbook = db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(sourceId || '');
  if (!playbook) fail(400, '未找到可用的来源预案，请等待生成完成或选择已有模板');
  const rows = db.prepare('SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(sourceId);
  if (!rows.length || rows.length > 60) fail(400, '来源预案必须包含 1–60 个步骤');
  const config = json(pipeline.config, {});
  const content = {
    name: playbook.name,
    notes: '',
    target: pipeline.target,
    authorization_scope: config.authorization_scope || '',
    source_playbook_id: sourceId,
    source_playbook: playbook,
    steps: rows.map(step => ({
      ...step,
      args_template: args(step.args_template),
      input_variables: parseVariableContract(step.input_variables),
      output_variables: parseVariableContract(step.output_variables),
      optional: !!step.optional,
    })),
    suggestions: [],
  };
  db.prepare("INSERT INTO task_plans (pipeline_id, state, content) VALUES (?, 'draft', ?)")
    .run(pipeline.pipeline_id, JSON.stringify(content));
  record(db, pipeline.pipeline_id, actor, 'create');
  return getTaskPlan(db, pipeline.pipeline_id);
}

export function saveTaskPlan(db, pipeline, actor, body) {
  const plan = checkedPlan(db, pipeline, body.revision, ['draft']);
  const input = body.content;
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, '缺少预案内容');
  const name = text(input.name, 200, '预案名称').trim();
  if (!name) fail(400, '预案名称不能为空');
  const notes = text(input.notes, 6000, '约束和备注');
  if (!Array.isArray(input.steps) || !input.steps.length || input.steps.length > 60) fail(400, '预案必须包含 1–60 个步骤');
  const used = new Set();
  const steps = input.steps.map(step => {
    const original = plan.content.steps.find(source => source.step_id === step?.step_id);
    if (!original || original.tool_id !== step.tool_id || used.has(step.step_id)) fail(400, '不可伪造步骤、改变工具或重复步骤');
    used.add(step.step_id);
    const stepName = text(step.name, 200, '步骤名称').trim();
    if (!stepName || typeof step.optional !== 'boolean') fail(400, '步骤名称或可选标记格式错误');
    return { ...original, name: stepName, args_template: args(step.args_template), optional: step.optional };
  });
  if (!Array.isArray(input.suggestions) || input.suggestions.length !== plan.content.suggestions.length)
    fail(400, '请通过候选转化入口添加建议');
  const suggestions = plan.content.suggestions.map((source, index) => {
    const item = input.suggestions[index];
    if (item?.id !== source.id || !['pending', 'accepted', 'rejected'].includes(item.status)) fail(400, '候选建议状态错误');
    return { ...source, status: item.status };
  });
  return update(db, pipeline.pipeline_id, actor, 'save', 'draft', { ...plan.content, name, notes, steps, suggestions });
}

export function addTaskPlanSuggestion(db, pipeline, actor, body) {
  const plan = checkedPlan(db, pipeline, body.revision, ['draft']);
  const categories = ['risk_assessment', 'tech_stack', 'attack_surface', 'recommended_strategy'];
  if (!categories.includes(body.category) || !Number.isInteger(body.index) || body.index < 0) fail(400, '候选来源无效');
  const analysis = json(pipeline.analysis_result, {});
  const raw = analysis[body.category];
  const items = Array.isArray(raw) ? raw : raw === undefined || raw === null ? [] : [raw];
  const value = items[body.index];
  if (value === undefined || !isDeepStrictEqual(value, body.source)) fail(409, '分析来源已变化，请刷新智能分析后重新选择');
  if (plan.content.suggestions.some(item => item.category === body.category && item.index === body.index && isDeepStrictEqual(item.source, value)))
    fail(409, '此候选项已加入草稿');
  if (plan.content.suggestions.length >= 30 || JSON.stringify(value).length > 10000) fail(400, '候选数量或内容超出限制');
  const suggestion = { id: randomUUID(), category: body.category, index: body.index, source: value,
    scan_task_ids: (pipeline.scan_task_id || '').split(',').filter(Boolean), status: 'pending' };
  return update(db, pipeline.pipeline_id, actor, 'add_suggestion', 'draft',
    { ...plan.content, suggestions: [...plan.content.suggestions, suggestion] });
}

export function transitionTaskPlan(db, pipeline, actor, action, body) {
  const allowed = { submit: ['draft'], reopen: ['submitted', 'rejected'], reject: ['submitted'], approve: ['submitted'] };
  if (!allowed[action]) fail(400, '未知预案操作');
  if (['reject', 'approve'].includes(action) && actor.role !== 'admin') fail(403, '只有管理员可以审批任务预案');
  const plan = checkedPlan(db, pipeline, body.revision, allowed[action]);
  const note = text(body.note ?? '', 2000, '审批意见').trim();
  if (action === 'reject' && !note) fail(400, '驳回时请填写原因');
  if (action === 'submit') {
    if (plan.content.suggestions.some(item => item.status === 'pending')) fail(400, '请先接受或拒绝所有候选建议，再提交审批');
    const config = json(pipeline.config, {});
    if (config.authorization_confirmed !== true) fail(400, '任务未记录授权确认，不能提审');
  }
  if (action !== 'approve') {
    const states = { submit: 'submitted', reopen: 'draft', reject: 'rejected' };
    return update(db, pipeline.pipeline_id, actor, action, states[action], plan.content, note);
  }
  const config = json(pipeline.config, {});
  if (config.authorization_confirmed !== true || plan.content.target !== pipeline.target
      || plan.content.authorization_scope !== (config.authorization_scope || '')) fail(409, '任务授权记录与提审快照不一致');
  if (config.auto_execute === false) fail(409, '此任务禁止自动执行，不能批准并执行');
  if (db.prepare("SELECT COUNT(*) AS count FROM pipelines WHERE status = 'running'").get().count >= 5)
    fail(429, '运行中任务数量已达上限，请等待其他任务结束后再审批');
  const playbookId = `task_plan_${randomUUID()}`;
  const source = plan.content.source_playbook;
  const metadata = json(source.metadata, {});
  metadata.task_plan = { pipeline_id: pipeline.pipeline_id, revision: plan.revision, approved_by: actor.sub };
  db.prepare(`INSERT INTO playbooks (playbook_id, name, description, target_type, not_suitable_for, baseline_group,
    expected_output_policy, roles_allowed, disable_auto_insert, enable_kg_context, requires_teacher_review,
    metadata, is_generated, generated_from, generated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 1, ?, datetime('now'))`)
    .run(playbookId, plan.content.name, source.description, source.target_type, source.not_suitable_for,
      source.baseline_group, source.expected_output_policy, source.roles_allowed, source.enable_kg_context,
      source.requires_teacher_review, JSON.stringify(metadata), plan.content.source_playbook_id);
  const insert = db.prepare(`INSERT INTO playbook_steps (playbook_id, step_index, step_id, name, tool_id, args_template,
    description, score, expected_mitre, payload_id, payload_variables, evidence_config, requires_teacher_review,
    optional, input_variables, output_variables) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  plan.content.steps.forEach((step, index) => insert.run(playbookId, index, step.step_id, step.name, step.tool_id,
    JSON.stringify(step.args_template), step.description, step.score, step.expected_mitre, step.payload_id,
    step.payload_variables, step.evidence_config, step.requires_teacher_review, step.optional ? 1 : 0,
    JSON.stringify(step.input_variables), JSON.stringify(step.output_variables)));
  db.prepare("UPDATE pipelines SET generated_playbook_id = ?, updated_at = datetime('now') WHERE pipeline_id = ?")
    .run(playbookId, pipeline.pipeline_id);
  db.prepare('UPDATE task_plans SET approved_playbook_id = ? WHERE pipeline_id = ?').run(playbookId, pipeline.pipeline_id);
  return update(db, pipeline.pipeline_id, actor, 'approve', 'approved', plan.content, note);
}
