import { resultCategory } from './scanResultCatalog.js';
import { verificationSummary } from './findingVerificationSummary.js';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { extractTopologyFromResults } from './topologyBuilder.js';
import { readTopologyOrigin } from './topologyOrigin.js';
import { normalizeTopologyTarget } from './nmapTopology.js';
import { sanitizeTaskLog } from './taskActivity.js';
import {isProgramMode, isProgramScan, programExecutionTarget} from './programScan.js';
import { pipelineScans } from './scanResultQuery.js';
import { hasScanCoverage } from './scanCoverage.js';
import { scopeBlockReason, scopeBlockingConditions, taskScope } from './taskScope.js';
import { appendDeclaredTopologyEntries } from './topologyWebEntries.js';

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

// Network evidence remains useful even when only source files are available.
// Exclude source/application records so a source server is not shown as the app.
export function networkOnlyResults(results) {
  const types=new Set(['open_port','service_info','host_discovery','network_context','network_link',
    'scan_evidence','scan_warning','lan_scope','lan_host_discovery']);
  return results.filter(row=>types.has(row.result_type) || row.result_type==='raw_output' && row.source_tool==='nmap');
}

export function sourceNetworkTopology(target, scans, results, flowId, owner, origin=null) {
  let host=''; try {host=normalizeTopologyTarget(target);} catch {}
  const topology=projectTopology(host,scans,networkOnlyResults(results),flowId,owner,origin);
  topology.summary+=' · 网络探测独立于程序执行';
  return topology;
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
    if (riskTypes.has(row.result_type) && ['vulnerability','credential'].includes(resultCategory(row))) {
      risks.push({ findingId: row.id, nodeId: node.id, name: row.result_type === 'credential' ? '凭证相关候选（不展示凭证内容）'
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
    nodes: nodeList, edges: [], risks, metadata: { projectionVersion: 3, owner, scanIds: scans.map(scan => scan.scan_task_id),
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

function annotateTaskGraph(db, pipeline, graph, results) {
  let scope = null;
  try { scope = taskScope(pipeline); } catch { /* Legacy task targets remain readable. */ }
  const covered = hasScanCoverage(db);
  const assets = covered
    ? db.prepare('SELECT * FROM task_assets WHERE pipeline_id=?').all(pipeline.pipeline_id) : [];
  const services = covered
    ? db.prepare('SELECT * FROM task_services WHERE pipeline_id=?').all(pipeline.pipeline_id) : [];
  const entries = covered
    ? db.prepare(`SELECT e.*,s.asset_id FROM task_entries e LEFT JOIN task_services s ON s.service_id=e.service_id
      WHERE e.pipeline_id=?`).all(pipeline.pipeline_id) : [];
  const checks = covered
    ? db.prepare(`SELECT c.*,s.asset_id FROM task_checks c LEFT JOIN task_services s ON s.service_id=c.service_id
      WHERE c.pipeline_id=?`).all(pipeline.pipeline_id) : [];
  const groupBy = (rows, key) => {
    const groups = new Map();
    for (const row of rows) {
      const id = row[key];
      if (!id) continue;
      const group = groups.get(id) || [];
      group.push(row);
      groups.set(id, group);
    }
    return groups;
  };
  const servicesByAsset = groupBy(services, 'asset_id');
  const entriesByAsset = groupBy(entries, 'asset_id');
  const checksByAsset = groupBy(checks, 'asset_id');
  const findingsByNode = groupBy(graph.risks, 'nodeId');
  const assetByHost = new Map(assets.map(asset => [asset.host.toLowerCase(), asset]));
  const graphHosts = new Set(graph.nodes.flatMap(node => [node.ip, node.hostName].filter(Boolean).map(value => value.toLowerCase())));
  for (const asset of assets) {
    const host = asset.host.toLowerCase();
    if (graphHosts.has(host)) continue;
    graph.nodes.push({ id: 'host-' + host, displayName: host, ip: isIP(host) ? host : '',
      hostName: isIP(host) ? '' : host, osName: '', osVersion: '', deviceType: 'host', vendor: '',
      status: asset.state === 'reachable' ? 'up' : 'unknown', note: '来自当前任务的资产清单',
      tags: ['asset-inventory'], x: graph.nodes.length * 260, y: 320, services: [],
      provenance: {kind:'asset',sources:[]}});
    graphHosts.add(host);
  }
  const rowSources = new Map();
  const lanScopeSources = new Map(), routeSources = new Map(), responseSources = new Map();
  const firstHopsByHost = new Map(), executorScans = new Map();
  const sourceByResultId = new Map();
  const appendSource = (map, key, source) => {
    if (!key) return;
    const sources = map.get(key) || [];
    if (!sources.some(item => item.result_id === source.result_id)) sources.push(source);
    map.set(key, sources);
  };
  for (const row of results) {
    let data;
    try { data = typeof row.result_data === 'string' ? JSON.parse(row.result_data) : row.result_data; } catch { continue; }
    if (!data || typeof data !== 'object') continue;
    const source = provenance(row).sources[0];
    sourceByResultId.set(row.id, source);
    for (const value of [data.host, data.ip, data.source, data.target, data.serverAddress, data.url]) {
      const host = address(value);
      appendSource(rowSources, host, source);
    }
    if (row.result_type === 'lan_scope') appendSource(lanScopeSources, data.cidr, source);
    if (row.result_type === 'network_link' && data.source && data.target)
      appendSource(routeSources, `${data.source}\0${data.target}`, source);
    if (row.result_type === 'host_discovery' && data.traceTarget && data.ttl === 1
        && data.host && data.evidence) {
      const hops = firstHopsByHost.get(data.host) || [];
      hops.push({ scanTaskId: row.scan_task_id, evidence: data.evidence, source });
      firstHopsByHost.set(data.host, hops);
    }
    if (data.host && !data.traceTarget && (
      row.result_type === 'host_discovery' && data.status === 'up'
      || row.result_type === 'open_port' && ['open','closed'].includes(data.state)))
      appendSource(responseSources, `${row.scan_task_id}\0${data.host}`, source);
    if (row.result_type === 'network_context' && Array.isArray(data.interfaces)) {
      for (const iface of data.interfaces) {
        if (!iface?.address) continue;
        appendSource(rowSources, iface.address, source);
        const ids = executorScans.get(iface.address) || new Set();
        ids.add(row.scan_task_id);
        executorScans.set(iface.address, ids);
      }
    }
  }
  for (const node of graph.nodes) {
    const host = (node.ip || node.hostName || '').toLowerCase();
    const asset = assetByHost.get(host) || assetByHost.get((node.hostName || '').toLowerCase());
    node.assetId = asset?.asset_id || null;
    if (asset) for (const service of servicesByAsset.get(asset.asset_id) || []) {
      if (node.services.some(item => item.port === String(service.port) && item.protocol === service.protocol)) continue;
      const serviceSource = sourceByResultId.get(service.source_record_id);
      node.services.push({port:String(service.port),protocol:service.protocol,service:text(service.name),
        product:'',version:'',state:service.state,note:'来自当前任务的服务清单',
        provenance:{kind:'asset',sources:serviceSource ? [serviceSource] : []}});
    }
    node.entries = asset ? (entriesByAsset.get(asset.asset_id) || [])
      .map(entry => ({ entryId: entry.entry_id, kind: entry.kind, value: text(entry.value, 500), state: entry.state,
        sourceRecordId: entry.source_record_id })) : [];
    node.checks = asset ? (checksByAsset.get(asset.asset_id) || [])
      .map(check => ({ checkId: check.check_id, type: check.check_type, scanType: check.scan_type,
        state: check.state, reason: text(check.reason), scanTaskId: check.scan_task_id,
        sourceRecordId: check.source_record_id })) : [];
    node.findings = (findingsByNode.get(node.id) || [])
      .map(risk => ({ findingId: risk.findingId, name: risk.name, severity: risk.severity,
        status: risk.status, verification: risk.verification || null,
        previousVerification: risk.previousVerification || null }));
    const candidate = node.ip || node.hostName;
    const sources = rowSources.get(host) || rowSources.get((node.hostName || '').toLowerCase()) || [];
    const observedHost = sources.some(source => ['host_discovery','lan_host_discovery'].includes(source.result_type));
    const eligible = Boolean(candidate && node.deviceType !== 'network_segment'
      && (asset || node.tags?.includes('target') || observedHost));
    const reason = !scope ? '旧任务缺少可校验的结构化测试范围'
      : eligible ? scopeBlockReason(scope, candidate, 'topology_scan') || scopeBlockingConditions(scope)[0] || null
        : '仅任务范围内的资产或实测主机可发起节点探测';
    node.scan = { eligible: eligible && !reason, reason };
    if (sources.length && (!node.provenance?.sources?.length || node.provenance.kind === 'inferred'))
      node.provenance = { kind: 'scan', sources };
    if (node.deviceType === 'network_segment')
      node.provenance = { kind: 'inferred', sources: lanScopeSources.get(node.hostName) || [] };
    const assetSource = asset && sourceByResultId.get(asset.source_record_id);
    if (assetSource && !node.provenance?.sources?.length)
      node.provenance = { kind: 'asset', sources: [assetSource] };
  }
  const byId = new Map(graph.nodes.map(node => [node.id, node]));
  for (const edge of graph.edges) {
    const source = byId.get(edge.sourceId), target = byId.get(edge.targetId);
    const sourceScanIds = executorScans.get(source?.ip) || new Set();
    if (edge.type === 'task-request') {
      edge.provenance = { kind: 'task', sources: [], description: edge.note };
      continue;
    }
    if (edge.provenance?.sources?.length) continue;
    const targetAddress = target?.ip || target?.hostName;
    let sources = [];
    if (edge.type === 'virtual-link') sources = lanScopeSources.get(source?.hostName) || [];
    if (edge.type === 'route') {
      sources = [...(routeSources.get(`${source?.ip || source?.hostName}\0${targetAddress}`) || [])];
      for (const hop of firstHopsByHost.get(targetAddress) || [])
        if (sourceScanIds.has(hop.scanTaskId) && edge.note.includes(hop.evidence)) sources.push(hop.source);
    }
    if (edge.type === 'reachability')
      for (const scanId of sourceScanIds)
        sources.push(...(responseSources.get(`${scanId}\0${targetAddress}`) || []));
    edge.provenance = { kind: edge.type === 'virtual-link' || !sources.length ? 'inferred' : 'scan',
      sources, description: edge.note };
  }
  graph.metadata.projectionVersion = 4;
  if (assets.length) graph.summary += ` · 任务资产清单 ${assets.length} 项`;
  graph.metadata.sourceFingerprint = createHash('sha256').update(JSON.stringify({
    base: graph.metadata.sourceFingerprint, assets, services, entries, checks,
    reviews: graph.risks.map(risk => [risk.verification || null, risk.previousVerification || null]),
  })).digest('hex');
  return graph;
}

export function pipelineTopology(db, pipeline) {
  let config={};
  try {config=typeof pipeline.config==='string' ? JSON.parse(pipeline.config) : pipeline.config || {};} catch {}
  const runtime=isProgramMode(config.scan_mode) ? programExecutionTarget(pipeline) : pipeline.target;
  const ids = [...new Set((pipeline.scan_task_id || '').split(',').map(identifier => identifier.trim()).filter(Boolean))];
  const discoveries = db.prepare("SELECT scan_task_id FROM scan_tasks WHERE scan_type IN ('topology_scan','port_scan') AND json_valid(parameters) AND json_extract(parameters, '$.pipeline_id') = ? AND created_by = ?")
    .all(pipeline.pipeline_id, pipeline.created_by);
  for (const row of discoveries) if (!ids.includes(row.scan_task_id)) ids.push(row.scan_task_id);
  const linked = pipelineScans(db, pipeline);
  const known = new Set(linked.map(scan => scan.scan_task_id));
  const matchesLegacyTarget = scan => {
    if (config.task_scope) return !scopeBlockReason(taskScope(pipeline), scan.target, scan.scan_type);
    if (scan.target === pipeline.target) return true;
    if (!['topology_scan', 'port_scan'].includes(scan.scan_type)) return false;
    try { return normalizeTopologyTarget(scan.target) === normalizeTopologyTarget(pipeline.target)
      || normalizeTopologyTarget(scan.target) === normalizeTopologyTarget(runtime); }
    catch { return false; }
  };
  const legacy = (ids.length ? db.prepare(`SELECT * FROM scan_tasks WHERE scan_task_id IN (${ids.map(() => '?').join(',')})
    AND created_by=? ORDER BY id`).all(...ids, pipeline.created_by) : [])
    .filter(scan => !known.has(scan.scan_task_id) && matchesLegacyTarget(scan));
  const extra = discoveries.map(row => row.scan_task_id).filter(id => !known.has(id))
    .map(id => db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=? AND created_by=?').get(id,pipeline.created_by))
    .filter(Boolean).filter(matchesLegacyTarget);
  const scans = [...linked, ...legacy, ...extra.filter(scan => !legacy.some(item => item.scan_task_id === scan.scan_task_id))];
  const results = scans.length ? db.prepare(`SELECT r.id, r.scan_task_id, r.result_type, r.result_data, r.severity, r.source_tool, r.captured_at,
      t.target AS scan_target FROM scan_results r JOIN scan_tasks t ON t.scan_task_id = r.scan_task_id
    WHERE r.scan_task_id IN (${scans.map(() => '?').join(',')})
      AND r.result_type != 'scan_error' ORDER BY r.id`).all(...scans.map(scan => scan.scan_task_id)) : [];
  const mapped = results.map(row=>({...row,scan_target:
    isProgramScan(scans.find(scan=>scan.scan_task_id===row.scan_task_id)?.scan_type) ? runtime : row.scan_target}));
  const graph = !runtime
    ? sourceNetworkTopology(pipeline.target, scans, results, pipeline.pipeline_id, pipeline.created_by, readTopologyOrigin(pipeline.config))
    : projectTopology(runtime, scans, mapped, pipeline.pipeline_id, pipeline.created_by, readTopologyOrigin(pipeline.config));
  if (graph.risks.length) {
    const ids = graph.risks.map(risk => risk.findingId).filter(Number.isInteger);
    if (ids.length) {
      const reviews = db.prepare(`SELECT v.* FROM source_verifications v WHERE v.finding_id IN (${ids.map(() => '?').join(',')})
        ORDER BY v.id`).all(...ids);
      const latest = new Map(reviews.map(review => [review.finding_id, review]));
      for (const risk of graph.risks) {
        const review = latest.get(risk.findingId);
        if (review) {
          let evidenceIds=[];
          try { evidenceIds=JSON.parse(review.evidence_ids || '[]'); } catch {}
          const summary = { status: review.status, runId: review.run_id,
            evidenceIds: Array.isArray(evidenceIds) ? evidenceIds : [], reviewedAt: review.created_at };
          if (pipeline.run_id && review.run_id === pipeline.run_id) risk.verification = summary;
          else risk.previousVerification = summary;
        }
      }
    }
  }
  for (const risk of graph.risks) {
    const verification=verificationSummary(db,risk.findingId,pipeline.pipeline_id);
    if(verification) risk.verification={...verification,status:verification.conclusion,runId:verification.run_id};
  }
  appendDeclaredTopologyEntries(annotateTaskGraph(db, pipeline, graph, results),scans,results);
  graph.metadata.sourceFingerprint=createHash('sha256').update(JSON.stringify({
    base:graph.metadata.sourceFingerprint,webEntries:graph.nodes.map(node=>[node.id,node.entries]),
  })).digest('hex');
  return graph;
}
