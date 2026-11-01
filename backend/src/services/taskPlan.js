import {isProgramMode, programExecutionTarget} from './programScan.js';
import { randomUUID } from 'crypto';
import { isDeepStrictEqual } from 'node:util';
import { parseVariableContract } from './executionVariables.js';
import { appendTaskLog } from './taskActivity.js';
import { assertPlaybookUse, canReadPlaybook, playbookScope } from './playbookAccess.js';
import { sourceTarget } from './sourceScanConnections.js';
import { validateSourceDemonstration } from './sourceVerification.js';
import { resultCategory } from './scanResultCatalog.js';

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

function isSourcePlanForTask(pipeline, playbook) {
  try {
    const source = json(playbook.metadata, {}).source_verification;
    return !!source?.demonstration && sourceTarget(programExecutionTarget(pipeline)) === source.target
      && String(pipeline.scan_task_id || '').split(',').includes(source.scan_task_id);
  } catch { return false; }
}

export function getTaskPlanSources(db, pipeline, actor) {
  const sourceMode = isProgramMode(json(pipeline.config, {}).scan_mode);
  return db.prepare(`SELECT p.*, (SELECT COUNT(*) FROM playbook_steps s WHERE s.playbook_id=p.playbook_id) AS steps_count
    FROM playbooks p ORDER BY p.generated_at DESC, p.name`).all().filter(playbook => {
    const scope = playbookScope(db, playbook);
    return canReadPlaybook(db, playbook, actor) && !scope.snapshot
      && (!scope.private || scope.owner === pipeline.created_by)
      && playbook.steps_count > 0 && playbook.steps_count <= 60
      && (!sourceMode || isSourcePlanForTask(pipeline, playbook));
  }).map(({playbook_id, name, steps_count}) => ({playbook_id, name, steps_count}));
}

function manualScanContinuationBlock(db, pipeline) {
  try {
    if (db.prepare("SELECT 1 FROM scan_tasks WHERE pipeline_id=? AND UPPER(status) NOT IN ('COMPLETED','PARTIAL','FAILED','CANCELLED')").get(pipeline.pipeline_id))
      return '扫描仍在运行或状态未确认，暂不能选择整体执行预案';
    if (db.prepare(`SELECT 1 FROM scan_tool_runs r JOIN scan_tasks s USING(scan_task_id) WHERE s.pipeline_id=?
      AND (r.state NOT IN ('completed','failed','timed_out','cancelled') OR r.completed_at IS NULL
        OR NOT json_valid(r.outcome) OR json_extract(r.outcome,'$.stopped') IS NOT 1)`).get(pipeline.pipeline_id))
      return '扫描工具停止未确认，暂不能继续执行';
    if (db.prepare("SELECT 1 FROM finding_verification_attempts WHERE pipeline_id=? AND (state IN ('queued','running','cancelling','unknown') OR stop_confirmed=0)").get(pipeline.pipeline_id))
      return '当前任务还有运行中或停止未确认的逐漏洞测试';
  } catch { return '当前服务缺少扫描停止状态记录，请更新服务后核对'; }
  return '';
}

export function taskPlanSelectionState(db, pipeline) {
  const state = {can_create_from_existing:false, requires_scan_failure_confirmation:false,
    pipeline_status:pipeline.status, reason:'当前任务不在待审批阶段'};
  if (pipeline.status === 'awaiting_approval') return {...state,can_create_from_existing:true,reason:''};
  if (pipeline.status !== 'failed' || pipeline.run_id) return state;
  const config = json(pipeline.config, {});
  if (config.task_mode === 'discovery' || config.workflow_mode === 'staged' || isProgramMode(config.scan_mode)
      || ['source','program'].includes(config.test_type)) return state;
  if (getTaskPlan(db,pipeline.pipeline_id)) return {...state,reason:'当前任务已有方案，请核对其执行状态，不要重复建立'};
  if (!db.prepare("SELECT 1 FROM pipeline_steps WHERE pipeline_id=? AND step_type='scan' AND status='failed'").get(pipeline.pipeline_id))
    return {...state,reason:'仅扫描失败且尚未执行的任务可从已有发现选择整体预案'};
  const blocked = manualScanContinuationBlock(db,pipeline);
  if (blocked) return {...state,reason:blocked};
  const findings = db.prepare(`SELECT r.result_type,r.result_data,r.source_tool,r.severity FROM scan_results r
    JOIN scan_tasks s USING(scan_task_id) WHERE s.pipeline_id=?`).iterate(pipeline.pipeline_id);
  let usable = false;
  for (const finding of findings) if (resultCategory(finding) === 'vulnerability') { usable = true; break; }
  if (!usable) return {...state,reason:'扫描没有保留可继续验证的漏洞候选，请先完成有效扫描'};
  return {...state,can_create_from_existing:true,requires_scan_failure_confirmation:true,
    reason:'扫描未完整成功，已有发现和失败记录会保留；可明确选择已有预案建立草稿，审阅确认后执行'};
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

export function createTaskPlan(db, pipeline, actor, playbookId, options = {}) {
  return db.transaction(() => createTaskPlanInternal(db,pipeline,actor,playbookId,options))();
}

function createTaskPlanInternal(db, pipeline, actor, playbookId, options) {
  const current = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(pipeline.pipeline_id);
  if (!current) fail(404,'任务不存在');
  pipeline = current;
  const selection = taskPlanSelectionState(db,pipeline);
  if (!selection.can_create_from_existing) fail(409,selection.reason);
  const manualContinuation = selection.requires_scan_failure_confirmation;
  if (manualContinuation && (options.continueAfterScanFailure !== true || typeof playbookId !== 'string' || !playbookId.trim()))
    fail(409,'请明确选择已有预案，并确认基于本次扫描保留的发现继续；扫描失败记录不会改为成功');
  if (getTaskPlan(db, pipeline.pipeline_id)) fail(409, '任务已有草稿，请刷新，不要重复初始化');
  const sourceId = playbookId || pipeline.generated_playbook_id;
  assertPlaybookUse(db, sourceId, actor, pipeline.created_by);
  const playbook = db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(sourceId || '');
  if (!playbook) fail(400, '未找到可用的来源预案，请等待生成完成或选择已有模板');
  const rows = db.prepare('SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(sourceId);
  if (!rows.length || rows.length > 60) fail(400, '来源预案必须包含 1–60 个步骤');
  const config = json(pipeline.config, {});
  if(isProgramMode(config.scan_mode)) {
    if(!isSourcePlanForTask(pipeline, playbook)) {
      fail(400,'请选择本任务程序发现生成的攻击测试预案，不能套用通用或其他任务预案');
    }
  }
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
  if (manualContinuation) {
    const result = json(pipeline.result, {});
    result.manual_scan_continuation = {previous_status:pipeline.status, scan_error:pipeline.error_message || null,
      selected_playbook_id:sourceId, requested_by:actor.sub, requested_at:new Date().toISOString()};
    db.prepare("UPDATE pipelines SET status='awaiting_approval',result=?,updated_at=datetime('now') WHERE pipeline_id=? AND status='failed'")
      .run(JSON.stringify(result),pipeline.pipeline_id);
    appendTaskLog(db,pipeline.pipeline_id,'用户选择已有预案继续审阅；扫描失败及已有发现保留，尚未执行','warn');
  }
  record(db, pipeline.pipeline_id, actor, 'create',manualContinuation ? '从扫描保留的发现选择已有预案，保留原扫描失败' : '');
  if (isProgramMode(config.scan_mode)) {
    db.prepare("UPDATE pipeline_steps SET status='completed',completed_at=datetime('now'),output_data=? WHERE pipeline_id=? AND step_type='generate'")
      .run(JSON.stringify({playbook_id:sourceId,method:'selected_source_demonstration',draft:true}),pipeline.pipeline_id);
  }
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
  if (['submit','approve'].includes(action) && json(pipeline.result,{}).manual_scan_continuation) {
    const blocked = manualScanContinuationBlock(db,pipeline);
    if (blocked) fail(409,blocked);
  }
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
  const enableExecution = config.auto_execute === false && body.enable_execution === true;
  if (config.auto_execute === false && !enableExecution)
    fail(409, '此任务未启用执行，请明确确认启用本任务执行后再批准');
  if (db.prepare("SELECT COUNT(*) AS count FROM pipelines WHERE status = 'running'").get().count >= 5)
    fail(429, '运行中任务数量已达上限，请等待其他任务结束后再审批');
  const playbookId = `task_plan_${randomUUID()}`;
  const source = plan.content.source_playbook;
  const metadata = json(source.metadata, {});
  if(metadata.source_verification?.demonstration) {
    try {
      validateSourceDemonstration(plan.content.steps.map(step=>({...step,...json(step.evidence_config,{})})),
        metadata.source_verification.finding_ids,metadata.source_verification.target);
    } catch(error) {fail(400,error.message);}
  }
  const taskName = typeof config.task_name === 'string' && config.task_name.trim()
    ? config.task_name.trim().slice(0,80) : pipeline.pipeline_id;
  const executionName = `${plan.content.name} · ${taskName} · 执行版本 v${plan.revision}`;
  metadata.task_plan = { pipeline_id: pipeline.pipeline_id, revision: plan.revision, approved_by: actor.sub,
    source_playbook_id: plan.content.source_playbook_id, source_name: source.name, task_name: taskName, display_name: executionName };
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
  if(isProgramMode(config.scan_mode)) {
    db.prepare("UPDATE pipeline_steps SET status='completed',completed_at=datetime('now'),output_data=? WHERE pipeline_id=? AND step_type='generate'")
      .run(JSON.stringify({playbook_id:playbookId,source_playbook_id:plan.content.source_playbook_id,
        method:'selected_source_demonstration',finding_ids:metadata.source_verification.finding_ids}),pipeline.pipeline_id);
  }
  if (enableExecution) {
    db.prepare('UPDATE pipelines SET config = ? WHERE pipeline_id = ?')
      .run(JSON.stringify({...config, auto_execute:true}), pipeline.pipeline_id);
  }
  return update(db, pipeline.pipeline_id, actor, 'approve', 'approved', plan.content,
    enableExecution ? [note, '管理员明确确认启用本任务执行，并批准当前提审版本'].filter(Boolean).join('\n') : note);
}
