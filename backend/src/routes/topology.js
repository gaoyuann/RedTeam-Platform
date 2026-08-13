import { Router } from 'express';
import { callLlm } from '../services/llmClient.js';

// ── Rule-based topology extraction from scan results ────────────────────
// This runs BEFORE the LLM call, so we always have a baseline topology
// even if the LLM fails or returns too few nodes.

function extractTopologyFromResults(target, results) {
  const nodes = new Map(); // ip -> node object
  const edges = [];

  // Ensure target itself is a node
  const targetIp = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').split(':')[0];
  if (targetIp && /^\d+\.\d+\.\d+\.\d+$/.test(targetIp)) {
    nodes.set(targetIp, {
      id: `host-${targetIp.replace(/\./g, '-')}`,
      displayName: targetIp,
      ip: targetIp,
      hostName: '',
      osName: '',
      osVersion: '',
      deviceType: 'host',
      vendor: '',
      status: 'up',
      note: '扫描目标',
      tags: [],
      x: 0, y: 0,
      services: [],
    });
  }

  for (const row of results) {
    let data = row.result_data;
    try {
      data = typeof data === 'string' ? JSON.parse(data) : data;
    } catch { data = {}; }

    const tool = row.source_tool || '';
    const type = row.result_type || '';

    // Skip raw_output — too noisy
    if (type === 'raw_output') continue;

    // Extract IP from data
    const ip = data.host || data.ip || data.target || '';
    const nodeIp = ip || targetIp;

    // Get or create node
    if (!nodeIp) continue;
    let node = nodes.get(nodeIp);
    if (!node) {
      node = {
        id: `host-${nodeIp.replace(/\./g, '-')}`,
        displayName: nodeIp,
        ip: nodeIp,
        hostName: '',
        osName: '',
        osVersion: '',
        deviceType: 'host',
        vendor: '',
        status: 'up',
        note: '',
        tags: [],
        x: 0, y: 0,
        services: [],
      };
      nodes.set(nodeIp, node);
    }

    // Extract service info from open_port results
    if (type === 'open_port' && data.port) {
      const service = {
        port: String(data.port),
        protocol: data.protocol || 'tcp',
        service: (data.service || '').split(/\s+/)[0] || '',
        product: '',
        version: '',
        state: data.state || 'open',
        note: '',
      };
      // Parse "Apache httpd 2.4.25 ((Debian))" from service field
      const svcStr = data.service || '';
      const parts = svcStr.match(/^(\S+)\s+(.*)/);
      if (parts) {
        service.service = parts[1];
        const productMatch = parts[2].match(/^(\S+)\s+(.*)/);
        if (productMatch) {
          service.product = productMatch[1];
          service.version = productMatch[2].replace(/[()]/g, '').trim();
        } else {
          service.product = parts[2];
        }
      }
      // Dedup
      if (!node.services.some(s => s.port === service.port && s.protocol === service.protocol)) {
        node.services.push(service);
      }
      // Detect OS from service strings
      if (svcStr.includes('Debian') && !node.osName) { node.osName = 'Debian'; }
      if (svcStr.includes('Ubuntu') && !node.osName) { node.osName = 'Ubuntu'; }
      if (svcStr.includes('CentOS') && !node.osName) { node.osName = 'CentOS'; }
      if (svcStr.includes('Windows') && !node.osName) { node.osName = 'Windows'; }
    }

    // Extract from vulnerability results
    if (type === 'vulnerability' || type === 'web_vuln') {
      const vulnName = data.name || data.finding || '';
      if (vulnName) {
        if (!node.note) {
          node.note = `发现漏洞: ${vulnName}`;
        } else if (node.note.length < 200) {
          node.note += `; ${vulnName.slice(0, 60)}`;
        }
      }
      // Infer HTTP service from web vuln results
      if (tool === 'nikto' || tool === 'nuclei') {
        if (!node.services.some(s => s.port === '80')) {
          node.services.push({ port: '80', protocol: 'tcp', service: 'http', product: '', version: '', state: 'open', note: '由Web扫描推断' });
        }
      }
    }

    // Extract from credential results
    if (type === 'credential') {
      node.note = node.note ? node.note + '; 凭证发现' : '凭证发现';
    }
  }

  // Assign positions in a circle if multiple nodes
  const nodeArr = [...nodes.values()];
  if (nodeArr.length > 1) {
    const radius = Math.max(200, nodeArr.length * 60);
    for (let i = 0; i < nodeArr.length; i++) {
      const angle = (2 * Math.PI * i) / nodeArr.length;
      nodeArr[i].x = Math.round(Math.cos(angle) * radius);
      nodeArr[i].y = Math.round(Math.sin(angle) * radius);
    }
  }

  // Create edges between nodes (gateway connections)
  if (nodeArr.length > 1) {
    for (let i = 1; i < nodeArr.length; i++) {
      edges.push({
        id: `edge-${i}`,
        sourceId: nodeArr[0].id,
        targetId: nodeArr[i].id,
        label: '网络连接',
        type: 'connection',
        note: '',
      });
    }
  }

  return {
    summary: `扫描发现 ${nodeArr.length} 台主机`,
    nodes: nodeArr,
    edges,
  };
}

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
  '只根据输入报告内容提取，不要编造不存在的主机。';

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

      // Fetch associated scan results
      const results = db
        .prepare(
          'SELECT * FROM scan_results WHERE scan_task_id = ? ORDER BY captured_at'
        )
        .all(scan_task_id);

      if (results.length === 0) {
        return res.status(400).json({
          status: 'error',
          error: { message: 'No scan results found for this scan task' },
        });
      }

      // ── Step 1: Rule-based extraction (always works) ────────────────
      const ruleBased = extractTopologyFromResults(task.target, results);
      const ruleNodeCount = ruleBased.nodes.size;

      // ── Step 2: Try LLM enhancement ──────────────────────────────────
      let topology = null;
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

      // ── Step 3: Merge or fallback ────────────────────────────────────
      if (topology && topology.nodes && topology.nodes.length >= ruleNodeCount) {
        // LLM produced enough nodes — use it, but merge in any rule-based services
        // that the LLM might have missed
        const llmNodeMap = new Map();
        for (const n of topology.nodes) {
          const key = n.ip || n.displayName || n.id;
          llmNodeMap.set(key, n);
        }
        for (const [, ruleNode] of ruleBased.nodes) {
          const llmNode = llmNodeMap.get(ruleNode.ip) || llmNodeMap.get(ruleNode.displayName);
          if (llmNode && ruleNode.services.length > 0) {
            // Add missing services from rule-based extraction
            for (const svc of ruleNode.services) {
              if (!llmNode.services.some(s => s.port === svc.port && s.protocol === svc.protocol)) {
                llmNode.services.push(svc);
              }
            }
          }
        }
      } else {
        // LLM failed or produced too few nodes — use rule-based result
        topology = {
          summary: ruleBased.summary + (topology ? '（LLM 增强不足，使用规则提取）' : '（LLM 不可用，使用规则提取）'),
          nodes: [...ruleBased.nodes.values()],
          edges: ruleBased.edges,
        };
      }

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
