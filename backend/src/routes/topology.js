import { Router } from 'express';
import { callLlm } from '../services/llmClient.js';

import { extractTopologyFromResults, mergeTopologyEnhancement } from '../services/topologyBuilder.js';

const SYSTEM_PROMPT =
  '你是一个网络拓扑结构化分析助手。请严格输出 JSON，不要输出 markdown，不要输出解释。' +
  '顶层字段必须包含 summary, nodes, edges。' +
  '不要把 nodes 改名为 hosts/devices/assets，也不要把 edges 改名为 links/connections。' +
  'nodes 每项字段：id, displayName, ip, hostName, osName, osVersion, deviceType, vendor, status, note, tags, x, y, services。' +
  '每个存活主机必须进入 nodes；字段缺失时使用空字符串或空数组。' +
  'services 每项字段：port, protocol, service, product, version, state, note。' +
  'port 字段必须输出字符串，例如 "80"，不要输出数字。' +
  'edges 每项字段：id, sourceId, targetId, label, type, note。' +
  '如果缺少位置坐标，请为每个节点补充 x/y 数值。' +
  '只补充输入中已有主机的系统和厂商描述；不要编造主机、服务或连接关系。';

function buildUserPrompt(target, results) {
  const lines = [`扫描目标: ${target || '未知'}\n`];

  for (const row of results) {
    const data = row.result_data;
    const tool = row.source_tool || 'unknown';
    const type = row.result_type || 'unknown';

    let content;
    try {
      content = typeof data === 'string' ? JSON.parse(data) : data;
    } catch {
      content = data;
    }

    const formatted =
      typeof content === 'object'
        ? JSON.stringify(content, null, 2)
        : String(content);

    lines.push(`--- ${tool} / ${type} ---`);
    lines.push(formatted);
  }

  return lines.join('\n');
}

export default function (db) {
  const router = Router();

  // Read-only projection of this pipeline's existing results. No scan or LLM call.
  router.get('/from-pipeline/:id', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
    if (req.user.role !== 'admin' && req.user.sub !== pipeline.created_by) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此任务' } });
    }
    const ids = [...new Set((pipeline.scan_task_id || '').split(',').map(id => id.trim()).filter(Boolean))];
    const discoveries = db.prepare(
      "SELECT scan_task_id FROM scan_tasks WHERE scan_type = 'topology_scan' AND json_valid(parameters) AND json_extract(parameters, '$.pipeline_id') = ?"
    ).all(pipeline.pipeline_id);
    ids.push(...discoveries.map(row => row.scan_task_id).filter(id => !ids.includes(id)));
    const results = ids.length ? db.prepare(
      'SELECT r.*, t.target AS scan_target FROM scan_results r JOIN scan_tasks t ON t.scan_task_id = r.scan_task_id WHERE r.scan_task_id IN ('
        + ids.map(() => '?').join(',') + ') ORDER BY r.captured_at'
    ).all(...ids) : [];
    const topology = extractTopologyFromResults(pipeline.target, results);
    topology.flowId = pipeline.pipeline_id;
    topology.target = pipeline.target;
    topology.generatedAt = new Date().toISOString();
    res.json({ status: 'ok', data: { topology } });
  });

  router.post('/generate-from-scan', async (req, res) => {
    try {
      const { scan_task_id } = req.body;

      if (!scan_task_id) {
        return res.status(400).json({
          status: 'error',
          error: { message: 'scan_task_id is required' },
        });
      }

      // Fetch the scan task
      const task = db
        .prepare('SELECT * FROM scan_tasks WHERE scan_task_id = ?')
        .get(scan_task_id);

      if (!task) {
        return res.status(404).json({
          status: 'error',
          error: { message: 'Scan task not found' },
        });
      }

      if (task.scan_type === 'topology_scan' && task.created_by
          && req.user.role !== 'admin' && req.user.sub !== task.created_by) {
        return res.status(403).json({ status: 'error', error: { message: '没有权限查看此拓扑探测' } });
      }

      if (task.status !== 'COMPLETED') {
        return res.status(409).json({
          status: 'error',
          error: { message: `Scan task is ${task.status}, topology requires a completed scan` },
        });
      }

      // Fetch associated scan results
      const results = db
        .prepare(
          'SELECT * FROM scan_results WHERE scan_task_id = ? ORDER BY captured_at'
        )
        .all(scan_task_id);

      // ── Step 1: Rule-based extraction (always works) ────────────────
      const ruleBased = extractTopologyFromResults(task.target, results);

      // ── Step 2: Try LLM enhancement ──────────────────────────────────
      let topology = null;
      if (results.length > 0 && task.scan_type !== 'topology_scan') {
        const userPrompt = buildUserPrompt(task.target, results);

        try {
          const llmResult = await callLlm(
            [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user', content: userPrompt },
            ],
            { temperature: 0.2, maxTokens: 8192 }
          );

          if (llmResult.ok) {
            // Strip markdown fences if present
            let content = llmResult.content.trim();
            content = content.replace(/^```json?\n?/, '').replace(/\n?```$/, '').trim();
            topology = JSON.parse(content);

            // Validate structure
            if (!topology.summary || !topology.nodes || !topology.edges) {
              topology = null;
            }
          }
        } catch (err) {
          // LLM failed or parse error — will fall back to rule-based
          topology = null;
        }
      }

      // Keep observed hosts, services and edges regardless of model output.
      topology = mergeTopologyEnhancement(ruleBased, topology);
      topology.flowId = task.scan_task_id;
      topology.target = task.target;
      topology.generatedAt = new Date().toISOString();

      res.json({ status: 'ok', data: { topology } });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        error: { message: err.message },
      });
    }
  });

  return router;
}
