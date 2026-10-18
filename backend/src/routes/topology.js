import { Router } from 'express';
import { callLlm } from '../services/llmClient.js';
import { pipelineTopology, sourceNetworkTopology } from '../services/topologyProjection.js';
import {isProgramScan, programExecutionTarget} from '../services/programScan.js';

import { extractTopologyFromResults, mergeTopologyEnhancement } from '../services/topologyBuilder.js';
import { randomUUID } from 'node:crypto';
import { normalizeTopologyTarget } from '../services/nmapTopology.js';
import { scopeBlockReason, scopeBlockingConditions, taskScope } from '../services/taskScope.js';
import { resolveTargetProfile } from '../services/targetProfileResolver.js';
import { requireActor } from '../middleware/recordAccess.js';

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
  router.use(requireActor(db));

  // Read-only projection of this pipeline's existing results. No scan or LLM call.
  router.get('/from-pipeline/:id', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
    if (req.user.role !== 'admin' && req.user.sub !== pipeline.created_by) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此任务' } });
    }
    const topology = pipelineTopology(db, pipeline);
    topology.flowId = pipeline.pipeline_id;
    topology.target = pipeline.target;
    topology.generatedAt = new Date().toISOString();
    res.json({ status: 'ok', data: { topology } });
  });

  // Resolve the node on the server: a client-side hand-drawn host or changed IP
  // cannot silently expand the pipeline's authorized scan scope.
  router.post('/from-pipeline/:id/node-scans', (req, res) => {
    try {
      const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(req.params.id);
      if (!pipeline) return res.status(404).json({status:'error',error:{message:'任务不存在'}});
      if (req.user.role !== 'admin' && req.user.sub !== pipeline.created_by)
        return res.status(403).json({status:'error',error:{message:'没有权限扫描此任务节点'}});
      const { node_id: nodeId, scan_type: scanType, request_id: requestId } = req.body || {};
      if (typeof nodeId !== 'string' || !nodeId || !['topology_scan','port_scan'].includes(scanType)
        || typeof requestId !== 'string' || !/^[a-zA-Z0-9_-]{8,128}$/.test(requestId))
        return res.status(400).json({status:'error',error:{message:'需要有效节点、扫描类型和 request_id'}});
      const existing = db.prepare('SELECT * FROM scan_tasks WHERE pipeline_id=? AND topology_request_id=?')
        .get(pipeline.pipeline_id, requestId);
      if (existing) {
        let parameters={}; try { parameters=JSON.parse(existing.parameters || '{}'); } catch {}
        if (parameters.node_id !== nodeId || existing.scan_type !== scanType)
          return res.status(409).json({status:'error',error:{message:'request_id 已用于其他节点扫描'}});
        return res.json({status:'ok',data:{scan_task_id:existing.scan_task_id,target:existing.target,
          scan_type:existing.scan_type,node_id:nodeId,status:existing.status,reused:true}});
      }
      const node = pipelineTopology(db,pipeline).nodes.find(item => item.id === nodeId);
      if (!node)
        return res.status(409).json({status:'error',error:{message:'该节点不是本任务可扫描的资产'}});
      const target = normalizeTopologyTarget(node.ip || node.hostName);
      if (target.includes('/')) return res.status(400).json({status:'error',error:{message:'节点扫描只接受单台主机'}});
      const scope = taskScope(pipeline);
      const blocked = scopeBlockReason(scope,target,scanType) || scopeBlockingConditions(scope)[0];
      if (blocked) return res.status(403).json({status:'error',error:{message:blocked}});
      if (!node.scan?.eligible)
        return res.status(409).json({status:'error',error:{message:'该节点不是本任务可扫描的资产'}});
      const active = db.prepare(`SELECT * FROM scan_tasks WHERE pipeline_id=? AND scan_type=?
        AND target=? AND topology_request_id IS NOT NULL AND json_valid(parameters)
        AND json_extract(parameters,'$.node_id')=? AND status IN ('PENDING','RUNNING')
        ORDER BY id DESC LIMIT 1`)
        .get(pipeline.pipeline_id,scanType,target,nodeId);
      if (active) return res.json({status:'ok',data:{scan_task_id:active.scan_task_id,target,
        scan_type:scanType,node_id:nodeId,status:active.status,reused:true}});
      const now = new Date().toISOString();
      const scanId = `scan_${randomUUID().slice(0,12)}`;
      const parameters = {pipeline_id:pipeline.pipeline_id,node_id:nodeId,asset_id:node.assetId,
        ...(scanType === 'port_scan' ? {discover_topology:true} : {}),timeout:300};
      db.prepare(`INSERT INTO scan_tasks
        (scan_task_id,target,scan_type,target_class,parameters,created_by,created_at,pipeline_id,topology_request_id)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(scanId,target,scanType,resolveTargetProfile(target).target_class,
        JSON.stringify(parameters),pipeline.created_by,now,pipeline.pipeline_id,requestId);
      return res.status(201).json({status:'ok',data:{scan_task_id:scanId,target,scan_type:scanType,
        node_id:nodeId,asset_id:node.assetId,status:'PENDING',reused:false}});
    } catch (error) {
      if (String(error.code || '').startsWith('SQLITE_CONSTRAINT')) {
        const row = db.prepare('SELECT * FROM scan_tasks WHERE pipeline_id=? AND topology_request_id=?')
          .get(req.params.id,req.body?.request_id);
        if (row) {
          let parameters={}; try {parameters=JSON.parse(row.parameters || '{}');} catch {}
          if (parameters.node_id === req.body?.node_id && row.scan_type === req.body?.scan_type)
            return res.json({status:'ok',data:{scan_task_id:row.scan_task_id,target:row.target,
              scan_type:row.scan_type,node_id:parameters.node_id,status:row.status,reused:true}});
        }
        return res.status(409).json({status:'error',error:{message:'节点扫描请求已存在'}});
      }
      return res.status(400).json({status:'error',error:{message:error.message}});
    }
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

      if (req.user.role !== 'admin' && req.user.sub !== task.created_by) {
        return res.status(403).json({ status: 'error', error: { message: '没有权限查看此拓扑探测' } });
      }

      if (!['COMPLETED','PARTIAL'].includes(task.status)) {
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
      const runtime=isProgramScan(task.scan_type) ? programExecutionTarget(task) : task.target;
      const ruleBased = runtime ? extractTopologyFromResults(runtime,results.map(row=>({...row,scan_target:runtime})))
        : sourceNetworkTopology(task.target,[task],results,null,task.created_by);

      // ── Step 2: Try LLM enhancement ──────────────────────────────────
      let topology = null;
      if (results.length > 0 && !['topology_scan','source_scan','program_scan'].includes(task.scan_type)) {
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
