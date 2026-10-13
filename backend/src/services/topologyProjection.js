import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { extractTopologyFromResults } from './topologyBuilder.js';
import { readTopologyOrigin } from './topologyOrigin.js';
import { normalizeTopologyTarget } from './nmapTopology.js';
import { sanitizeTaskLog } from './taskActivity.js';
import {isProgramMode, isProgramScan, programExecutionTarget} from './programScan.js';

function text(value, length = 200) {
  return typeof value === 'string' || typeof value === 'number' ? sanitizeTaskLog(value).slice(0, length) : '';
}

function address(value) {
  const input = text(value, 500).trim();
  if (/^(?:https?|tcp):\/\//i.test(input)) {
    try { return new URL(input).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { return ''; }
  }
  if (isIP(input)) return input.toLowerCase();
  const authority = input.split('/')[0];
  if (isIP(authority) && /^\d+$/.test(input.split('/')[1] || '')) return '';
  if (/^[a-z0-9._-]+(?::\d+)?$/i.test(authority)) return authority.split(':')[0].toLowerCase();
  return '';
}

function provenance(row, kind = 'scan') {
  return { kind, sources: row ? [{ scan_task_id: row.scan_task_id, result_id: row.id,
    tool: text(row.source_tool), result_type: row.result_type, captured_at: row.captured_at || '' }] : [] };
}

function addSources(destination, source) {
  for (const entry of source.sources)
    if (!destination.sources.some(existing => existing.result_id === entry.result_id)) destination.sources.push(entry);
}

export function projectTopology(target, scans, results, flowId, owner, origin = null) {
  const nodes = new Map();
  const risks = [];
  const scanTypes = new Set(['open_port', 'service_info', 'host_discovery', 'http_probe', 'technology_detection', 'application_observation']);
  const riskTypes = new Set(['vulnerability', 'web_vuln', 'sql_injection', 'misconfiguration', 'auth_finding', 'credential', 'source_finding', 'program_finding']);
  function nodeFor(host, source) {
    if (!host) return null;
    let node = nodes.get(host);
    if (!node) {
      node = { id: 'host-' + createHash('sha256').update(host).digest('hex').slice(0, 20), displayName: host,
        ip: isIP(host) ? host : '', hostName: isIP(host) ? '' : host, osName: '', osVersion: '', deviceType: 'host',
        vendor: '', status: 'unknown', note: '', tags: [], x: 0, y: 0, services: [], provenance: source };
      nodes.set(host, node);
    } else {
      if (node.provenance.kind === 'target' && source.kind !== 'target') node.provenance.kind = source.kind;
      addSources(node.provenance, source);
    }
    return node;
  }
  const targetHost = address(target);
  for (const row of results) {
    if (!scanTypes.has(row.result_type) && !riskTypes.has(row.result_type)) continue;
    let data;
    try { data = typeof row.result_data === 'string' ? JSON.parse(row.result_data) : row.result_data; } catch { continue; }
    if (!data || typeof data !== 'object' || Array.isArray(data)) continue;
    if (row.result_type === 'application_observation') {
      try {
        const url = new URL(data.url), runtime = new URL(row.scan_target || target);
        if (!['http:', 'https:', 'tcp:'].includes(url.protocol) || url.username || url.password
            || url.protocol !== runtime.protocol || url.hostname !== runtime.hostname || url.port !== runtime.port) continue;
      } catch { continue; }
    }
    const port = typeof data.port === 'number' || typeof data.port === 'string' && /^\d+$/.test(data.port) ? Number(data.port) : NaN;
    if (['open_port', 'service_info'].includes(row.result_type) && (!Number.isInteger(port) || port < 1 || port > 65535)) continue;
    const host = address(data.host || data.ip || data.target || data.url) || targetHost;
    const node = nodeFor(host, provenance(row));
    if (!node) continue;
    if (riskTypes.has(row.result_type)) {
      risks.push({ nodeId: node.id, name: row.result_type === 'credential' ? '凭证相关候选（不展示凭证内容）'
        : text(data.title || data.name || data.finding || data.template || row.result_type), severity: text(row.severity || data.severity),
      status: 'candidate', provenance: provenance(row) });
      continue;
    }
    if (row.result_type === 'host_discovery' && ['up', 'alive'].includes(data.status || data.state)) node.status = 'up';
    if (Number.isInteger(port) && port > 0 && port <= 65535 && ['open_port', 'service_info'].includes(row.result_type)) {
      const protocol = ['tcp', 'udp'].includes(data.protocol) ? data.protocol : 'tcp';
      const state = text(data.state) || (row.result_type === 'open_port' ? 'open' : 'unknown');
      const existing = node.services.find(service => service.port === String(port) && service.protocol === protocol);
      if (existing) {
        addSources(existing.provenance, provenance(row));
        existing.provenance.kind = 'scan';
        existing.state = state;
        existing.service = text(data.service).split(/\s+/)[0] || existing.service;
        existing.product = text(data.product) || existing.product;
        existing.version = text(data.version) || existing.version;
        existing.note = '';
      }
      else node.services.push({ port: String(port), protocol, service: text(data.service).split(/\s+/)[0],
        product: text(data.product), version: text(data.version), state, note: '', provenance: provenance(row) });
      if (state === 'open') node.status = 'up';
      node.osName = node.osName || text(data.os);
    }
    if (['http_probe', 'technology_detection'].includes(row.result_type)) {
      let url;
      try { url = new URL(data.url || data.target || target); } catch { continue; }
      if (!['http:', 'https:'].includes(url.protocol)) continue;
      if (address(url.hostname.replace(/^\[|\]$/g, '')) !== host) continue;
      const inferredPort = url.port || (url.protocol === 'https:' ? '443' : '80');
      if (!node.services.some(service => service.port === inferredPort && service.protocol === 'tcp'))
        node.services.push({ port: inferredPort, protocol: 'tcp', service: url.protocol.slice(0, -1), product: '', version: '',
          state: 'unknown', note: '端口由 URL 推断，不代表端口扫描验证', provenance: provenance(row, 'inferred') });
    }
  }
  if (!nodes.size && targetHost) nodeFor(targetHost, provenance(null, 'target'));
  const nodeList = [...nodes.values()];
  for (const [index, node] of nodeList.entries()) {
    const angle = 2 * Math.PI * index / Math.max(1, nodeList.length);
    node.x = Math.round(Math.cos(angle) * (nodeList.length > 1 ? 220 : 0));
    node.y = Math.round(Math.sin(angle) * (nodeList.length > 1 ? 220 : 0));
  }
  const observed = nodeList.filter(node => node.provenance.kind !== 'target').length;
  const fingerprint = createHash('sha256').update(JSON.stringify({ target, scans, results })).digest('hex');
  const projection = { flowId, target, generatedAt: new Date().toISOString(),
    summary: `扫描关联资产 ${observed} 项${observed ? '' : '（目标占位不代表存活）'} · 未提供网络连接证据`,
    nodes: nodeList, edges: [], risks, metadata: { projectionVersion: 2, owner, scanIds: scans.map(scan => scan.scan_task_id),
      sourceCount: results.filter(row => !['raw_output', 'scan_error'].includes(row.result_type)).length,
      sourceFingerprint: fingerprint, source: 'structured_scan_results', manuallyEdited: false } };
  // Preserve the task projection contract while retaining observed network relations.
  const graph = extractTopologyFromResults(target, results, { includeOrigin: !!origin, origin });
  const byAddress = new Map(nodeList.map(node => [node.ip || node.hostName, node]));
  const remap = new Map();
  for (const node of graph.nodes) {
    const previous = byAddress.get(node.ip || node.hostName);
    if (previous) {
      remap.set(previous.id, node.id);
      node.provenance = previous.provenance;
      for (const service of previous.services) {
        const existing = node.services.find(item => item.port === service.port && item.protocol === service.protocol);
        if (existing) Object.assign(existing, service);
        else node.services.push(service);
      }
    } else {
      node.provenance = { kind: 'inferred', sources: [], description: node.note };
    }
  }
  for (const node of nodeList) if (!remap.has(node.id)) graph.nodes.push(node);
  for (const risk of risks) risk.nodeId = remap.get(risk.nodeId) || risk.nodeId;
  for (const edge of graph.edges) {
    const destination=graph.nodes.find(node=>node.id===edge.targetId);
    const sources=edge.type==='application-request' ? results.filter(row=>{
      if(row.result_type!=='application_observation') return false;
      try {
        const data=typeof row.result_data==='string' ? JSON.parse(row.result_data) : row.result_data;
        const url=new URL(data.url),runtime=new URL(row.scan_target || target);
        return data.connected===true && !url.username && !url.password
          && ['http:','https:','tcp:'].includes(url.protocol) && url.protocol===runtime.protocol
          && url.hostname===runtime.hostname && url.port===runtime.port
          && address(url.href)===(destination?.ip || destination?.hostName);
      } catch {return false;}
    }).flatMap(row=>provenance(row).sources) : [];
    edge.provenance={kind:['route','application-request'].includes(edge.type)?'scan':'inferred',sources,description:edge.note};
  }
  return { ...projection, nodes: graph.nodes, edges: graph.edges, summary: graph.summary };
}

export function pipelineTopology(db, pipeline) {
  let config={};
  try {config=typeof pipeline.config==='string' ? JSON.parse(pipeline.config) : pipeline.config || {};} catch {}
  const runtime=isProgramMode(config.scan_mode) ? programExecutionTarget(pipeline) : pipeline.target;
  const ids = [...new Set((pipeline.scan_task_id || '').split(',').map(identifier => identifier.trim()).filter(Boolean))];
  const discoveries = db.prepare("SELECT scan_task_id FROM scan_tasks WHERE scan_type = 'topology_scan' AND json_valid(parameters) AND json_extract(parameters, '$.pipeline_id') = ? AND created_by = ?")
    .all(pipeline.pipeline_id, pipeline.created_by);
  for (const row of discoveries) if (!ids.includes(row.scan_task_id)) ids.push(row.scan_task_id);
  const scans = (ids.length ? db.prepare(`SELECT * FROM scan_tasks
    WHERE scan_task_id IN (${ids.map(() => '?').join(',')}) AND created_by = ? ORDER BY scan_task_id`)
    .all(...ids, pipeline.created_by) : []).filter(scan => {
      if (scan.target === pipeline.target) return true;
      if (scan.scan_type !== 'topology_scan') return false;
      try { return normalizeTopologyTarget(scan.target) === normalizeTopologyTarget(pipeline.target); }
      catch { return false; }
    });
  const results = scans.length ? db.prepare(`SELECT r.id, r.scan_task_id, r.result_type, r.result_data, r.severity, r.source_tool, r.captured_at,
      t.target AS scan_target FROM scan_results r JOIN scan_tasks t ON t.scan_task_id = r.scan_task_id
    WHERE r.scan_task_id IN (${scans.map(() => '?').join(',')})
      AND r.result_type != 'scan_error' ORDER BY r.id`).all(...scans.map(scan => scan.scan_task_id)) : [];
  if(!runtime) {
    const topology=projectTopology('',scans,[],pipeline.pipeline_id,pipeline.created_by);
    topology.summary='仅提供源码输入，尚无程序运行地址；源码目录不作为运行资产或连接证据';
    return topology;
  }
  return projectTopology(runtime, scans, results.map(row=>({...row,scan_target:
    isProgramScan(scans.find(scan=>scan.scan_task_id===row.scan_task_id)?.scan_type) ? runtime : row.scan_target})),
    pipeline.pipeline_id, pipeline.created_by, readTopologyOrigin(pipeline.config));
}
