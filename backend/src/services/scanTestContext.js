import { currentActor } from '../middleware/recordAccess.js';
import { hasScanIntegrity } from './scanResultStore.js';
import { insertNumberedTask } from './taskIdentity.js';
import { normalizeTaskScope } from './taskScope.js';
import { pipelineScans } from './scanResultQuery.js';
import { appendTaskLog } from './taskActivity.js';

const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const json = value => { try { return JSON.parse(value || '{}'); } catch { return {}; } };

// Organize an existing scan; never dispatch a scan, model call or attack here.
export function continueScanTest(db, actor, scanId) {
  if (!hasScanIntegrity(db)) fail(503, '扫描关联迁移尚未安装，请更新后端后重试');
  return db.transaction(() => {
    if (!currentActor(db, actor)) fail(401, '登录身份已失效，请重新登录');
    const scan = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(scanId);
    if (!scan) fail(404, '扫描不存在');
    if (scan.created_by !== actor.sub && actor.role !== 'admin') fail(403, '没有权限访问此扫描');
    const linked = db.prepare(`SELECT * FROM pipelines WHERE pipeline_id=? OR
      instr(',' || replace(coalesce(scan_task_id,''),' ','') || ',', ',' || ? || ',')>0 ORDER BY id`).all(scan.pipeline_id || '', scanId);
    if (linked.length) {
      if (linked.length !== 1 || linked[0].created_by !== scan.created_by
          || !pipelineScans(db, linked[0]).some(row => row.scan_task_id === scanId))
        fail(409, '扫描来源关联不一致，请核对原测试任务');
      if (json(linked[0].config).task_mode === 'discovery') fail(409, '这是资产探测记录，请从资产或拓扑选择具体目标发起漏洞扫描');
      return { pipeline_id: linked[0].pipeline_id, task_no: linked[0].task_no, scan_task_id: scanId, reused: true };
    }
    if (scan.pipeline_id) fail(409, '扫描的原测试任务不存在，请核对来源');
    if (scan.created_by !== actor.sub) fail(403, '请由扫描所有者建立测试关联');
    if (!['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(scan.status)) fail(409, '请等待扫描结束后继续编制预案与验证');
    const calls = db.prepare('SELECT state,completed_at,outcome FROM scan_tool_runs WHERE scan_task_id=?').all(scanId);
    if (calls.some(call => call.state === 'running' || !call.completed_at || json(call.outcome)?.stopped !== true))
      fail(409, '扫描工具停止情况未确认，请核对原扫描后再继续');
    if (!['port_scan', 'vuln_scan', 'web_scan', 'web_scan_nikto', 'web_scan_sqlmap', 'web_parameter_scan', 'api_fuzz', 'auth_audit', 'brute_force'].includes(scan.scan_type))
      fail(400, '此扫描类型请使用原专项测试流程');
    if (db.prepare(`SELECT count(*) n FROM pipelines WHERE created_by=? AND status IN ('created','running')`).get(actor.sub).n >= 20)
      fail(429, '活跃测试任务数量已达上限(20)');
    const config = { workflow_mode: 'staged', task_mode: 'assessment', task_name: `扫描后续测试 · ${scan.target}`,
      auto_execute: false, require_approval: true, source_scan_task_id: scanId,
      authorization_confirmed: false, authorization_scope: scan.target,
      task_scope: normalizeTaskScope({}, scan.target) };
    const { row } = insertNumberedTask(db, { target: scan.target, config, owner: actor.sub, ownerRole: actor.role });
    // The imported stage has ended. Verification attempts retain their own lifecycle
    // and conclusions, including failures; pipeline completion claims no success.
    const status = scan.status === 'FAILED' ? 'failed' : scan.status === 'CANCELLED' ? 'cancelled' : 'completed';
    db.prepare('UPDATE pipelines SET scan_task_id=?,status=? WHERE pipeline_id=?').run(scanId, status, row.pipeline_id);
    const linkedScan = db.prepare("UPDATE scan_tasks SET pipeline_id=? WHERE scan_task_id=? AND (pipeline_id IS NULL OR pipeline_id='')").run(row.pipeline_id, scanId);
    if (linkedScan.changes !== 1) fail(409, '扫描来源已变化，请刷新后重试');
    db.prepare(`INSERT INTO pipeline_steps(pipeline_id,step_order,step_type,status,output_data,completed_at)
      VALUES (?,0,'scan',?,?,?)`).run(row.pipeline_id, status, JSON.stringify({ scan_task_ids: [scanId], imported: true }), scan.completed_at || null);
    appendTaskLog(db, row.pipeline_id, '已关联原扫描及发现；后续预案、验证与报告独立操作，尚未执行攻击验证');
    return { pipeline_id: row.pipeline_id, task_no: row.task_no, scan_task_id: scanId, reused: false };
  }).immediate();
}
