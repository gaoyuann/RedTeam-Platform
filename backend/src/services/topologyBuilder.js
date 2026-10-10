import { isIP } from 'node:net';
import { parseNmapResults, selectLanDiscoveryScope } from './nmapTopology.js';
import { isLoopbackAddress } from './topologyOrigin.js';

function hostKey(value) {
  let text = String(value || '').trim();
  if (/^https?:\/\//i.test(text)) {
    try { text = new URL(text).hostname; } catch { return ''; }
  } else if (!isIP(text) && /^[^/:]+:\d+$/.test(text)) {
    text = text.replace(/:\d+$/, '');
  }
  text = text.replace(/^\[|\]$/g, '');
  if (!text || /\s|\//.test(text)) return '';
  return text.toLowerCase();
}

function ipv4Number(value) {
  return value.split('.').reduce((n, part) => ((n << 8) | Number(part)) >>> 0, 0);
}

function cidrScope(value) {
  const match = String(value || '').match(/^([^/]+)\/(\d+)$/);
  if (!match || isIP(match[1]) !== 4 || Number(match[2]) > 32) return null;
  const prefix = Number(match[2]);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipv4Number(match[1]) & mask) >>> 0;
  const address = [24, 16, 8, 0].map(shift => (network >>> shift) & 255).join('.');
  return { cidr: address + '/' + prefix, mask, network };
}

function dataOf(row) {
  try { return typeof row.result_data === 'string' ? JSON.parse(row.result_data) : row.result_data; }
  catch { return null; }
}

export function extractTopologyFromResults(target, results, { includeOrigin = false, origin = null } = {}) {
  const nodes = new Map(), edges = new Map(), hopDepths = new Map();
  const nodeFor = value => {
    const key = hostKey(value);
    if (!key) return null;
    if (!nodes.has(key)) nodes.set(key, {
      id: 'host-' + key, displayName: key, ip: isIP(key) ? key : '',
      hostName: isIP(key) ? '' : key, osName: '', osVersion: '', deviceType: 'host',
      vendor: '', status: 'unknown', note: '', tags: [], x: 0, y: 0, services: [],
    });
    return nodes.get(key);
  };
  const appendNote = (node, note) => {
    if (note && !node.note.includes(note)) node.note = [node.note, note].filter(Boolean).join('\n').slice(0, 2000);
  };
  // Older scans may have only raw Nmap output. Reparse it without treating
  // arbitrary report text or a target range as a discovered host.
  const records = [...results];
  for (const row of results) {
    const data = dataOf(row);
    if (row.source_tool === 'nmap' && row.result_type === 'raw_output' && data?.output) {
      records.push(...parseNmapResults(data.output, { assumedUp: true }).map(r => ({
        ...r, scan_task_id: row.scan_task_id, scan_target: row.scan_target,
      })));
    }
  }
  const knownHostsByScan = new Map();
  for (const row of records) {
    const data = dataOf(row);
    if (row.result_type !== 'lan_host_discovery' && data?.host && data.deviceType !== 'router' && row.result_type !== 'network_link'
        && (!data.traceTarget || data.traceTarget === data.host)) {
      const set = knownHostsByScan.get(row.scan_task_id) || new Set();
      set.add(hostKey(data.host));
      knownHostsByScan.set(row.scan_task_id, set);
    }
  }
  for (const row of records) {
    const data = dataOf(row);
    if (!data || typeof data !== 'object' || Array.isArray(data)) continue;
    const type = row.result_type;
    if (type === 'network_link') {
      // Only structured route evidence becomes an observed link.
      if (data.type !== 'route' || !data.evidence || !isIP(data.source) || !isIP(data.target)) continue;
      const source = nodeFor(data.source), dest = nodeFor(data.target);
      if (!source || !dest || source.id === dest.id) continue;
      const id = 'route:' + source.id + '>' + dest.id;
      const existing = edges.get(id);
      if (existing) {
        if (!existing.note.includes(data.evidence)) existing.note += '\n' + data.evidence;
      } else edges.set(id, {
        id, sourceId: source.id, targetId: dest.id, label: '路由观测', type: 'route',
        note: data.evidence + '\n表示相邻响应跳点，不代表物理布线。',
      });
      continue;
    }
    if (!['host_discovery', 'open_port', 'vulnerability', 'web_vuln', 'credential',
          'http_probe', 'technology_detection'].includes(type)) continue;
    const explicitHost = data.host || data.ip || data.target || data.url;
    const known = knownHostsByScan.get(row.scan_task_id);
    // A legacy port without host context cannot safely be assigned to a CIDR
    // or to one of several hosts recovered from raw output.
    const fallback = known?.size === 1 ? [...known][0]
      : known?.size > 1 ? '' : (row.scan_target || target);
    const node = nodeFor(explicitHost || fallback);
    if (!node) continue;
    if (type === 'host_discovery') {
      if (data.status === 'up') node.status = 'up';
      if (data.hostName) node.hostName = String(data.hostName);
      if (data.vendor) node.vendor = String(data.vendor);
      if (data.deviceType === 'router') node.deviceType = 'router';
      appendNote(node, data.evidence);
      if (data.traceTarget && Number.isInteger(data.ttl) && data.ttl > 0) {
        if (!node.tags.includes('trace-hop')) node.tags.push('trace-hop');
        hopDepths.set(node.id, Math.min(hopDepths.get(node.id) ?? Infinity, data.ttl));
      }
      if (data.mac) appendNote(node, 'MAC: ' + data.mac);
    }
    if (type === 'open_port' && Number(data.port) > 0 && Number(data.port) <= 65535) {
      const parts = String(data.service || '').match(/^(\S+)(?:\s+(\S+))?(?:\s+(.*))?$/);
      const svc = {
        port: String(data.port), protocol: data.protocol || 'tcp',
        service: String(data.service || '').split(/\s+/)[0],
        product: data.product || parts?.[2] || '', version: data.version || parts?.[3] || '',
        state: data.state || 'unknown', note: '',
      };
      const index = node.services.findIndex(s => s.port === svc.port && s.protocol === svc.protocol);
      if (index < 0) node.services.push(svc);
      else if (node.services[index].state !== 'open') node.services[index] = svc;
      // Filtered / open|filtered are not proof of a live host.
      if (['open', 'closed'].includes(svc.state)) node.status = 'up';
      const os = String(data.service || '').match(/\b(Debian|Ubuntu|CentOS|Windows)\b/i);
      if (os && !node.osName) node.osName = os[1];
    }
    if (['vulnerability', 'web_vuln'].includes(type)) appendNote(node, data.name || data.finding || '');
    if (type === 'credential') appendNote(node, '凭证发现');
  }

  // Route configuration identifies the executor's outgoing interface only.
  // It never creates a gateway node or an observed forwarding link.
  const targetNode = nodeFor(target);
  if (targetNode) targetNode.tags.push('target');
  for (const row of records.filter(r => r.result_type === 'network_context')) {
    const data = dataOf(row);
    if (!Array.isArray(data?.interfaces) || !Array.isArray(data?.routes)) continue;
    const sameScan = records.filter(r => r.scan_task_id === row.scan_task_id);
    const scanTargets = new Set(knownHostsByScan.get(row.scan_task_id) || []);
    const exactTarget = hostKey(row.scan_target || target);
    if (isIP(exactTarget)) scanTargets.add(exactTarget);
    for (const key of scanTargets) {
      const dest = nodeFor(key);
      if (!dest || isIP(dest.ip) !== 4) continue;
      if (!dest.tags.includes('target')) dest.tags.push('target');
      const route = data.routes.map(r => ({ ...r, scope: cidrScope(r.destination) }))
        .filter(r => r.scope && ((ipv4Number(dest.ip) & r.scope.mask) >>> 0) === r.scope.network)
        .sort((a, b) => b.scope.cidr.split('/')[1] - a.scope.cidr.split('/')[1] || a.metric - b.metric)[0];
      if (!route) continue;
      const candidates = data.interfaces.filter(i => i.device === route.device && isIP(i.address) === 4);
      const iface = candidates.find(i => {
        const scope = cidrScope(i.address + '/' + i.prefix);
        const hop = route.gateway && route.gateway !== '0.0.0.0' ? route.gateway : dest.ip;
        return scope && ((ipv4Number(hop) & scope.mask) >>> 0) === scope.network;
      }) || candidates[0];
      if (!iface) continue;
      const source = nodeFor(iface.address);
      source.deviceType = 'scanner';
      source.status = 'up';
      source.displayName = '服务器';
      if (!source.tags.includes('scanner')) source.tags.push('scanner');
      if (!source.tags.includes('server')) source.tags.push('server');
      appendNote(source, 'Nmap --iflist：扫描执行环境接口 ' + iface.device
        + '，地址 ' + iface.address + '/' + iface.prefix);
      appendNote(source, '目标路由配置：' + route.destination
        + (route.gateway ? '，下一跳 ' + route.gateway : '，本地链路')
        + '；该配置仅用于确定出口，不作为实际跳点证据。');
      if (data.executionMode) appendNote(source, '执行方式：' + data.executionMode);
      if (row.captured_at) appendNote(source, '采集时间：' + row.captured_at);
      if (source.id === dest.id) {
        appendNote(source, '任务目标与扫描执行端为同一地址。');
        continue;
      }
      const hops = sameScan.filter(r => r.result_type === 'host_discovery')
        .map(dataOf).filter(d => d?.traceTarget === dest.ip && d.evidence && isIP(d.host));
      for (const hop of hops.filter(d => d.ttl === 1)) {
        const first = nodeFor(hop.host);
        if (first.id === source.id) continue;
        const id = 'route:' + source.id + '>' + first.id;
        edges.set(id, { id, sourceId: source.id, targetId: first.id, type: 'route',
          label: '第 1 跳', note: hop.evidence + '\n起点来自同次扫描的出口接口；表示探测路径，不代表物理网线。' });
      }
      // A successful response proves communication, not a direct physical link.
      // Keep this separate from hop-by-hop evidence; missing hops stay missing.
      const response = sameScan.find(r => {
        const d = dataOf(r);
        return d?.host === dest.ip && !d.traceTarget && (
          (r.result_type === 'open_port' && ['open','closed'].includes(d.state))
          || (r.result_type === 'host_discovery' && d.status === 'up'));
      });
      if (!hops.length && response) {
        const d = dataOf(response);
        const id = 'response:' + source.id + '>' + dest.id;
        edges.set(id, { id, sourceId: source.id, targetId: dest.id,
          type: 'reachability', label: '目标响应',
          note: (d.evidence || 'Nmap ' + dest.ip + ' ' + d.port + '/' + d.protocol + ' ' + d.state)
            + '\n仅证明本次扫描收到目标地址的响应；不表示物理直连或中间没有网络设备。'
            + (response.captured_at ? '\n采集时间：' + response.captured_at : '') });
      }
    }
  }

  // Replace a hostname placeholder with its resolved IP when Nmap supplies it.
  for (const node of [...nodes.values()]) {
    const alias = hostKey(node.hostName);
    if (!node.ip || !alias || alias === node.ip || !nodes.has(alias)) continue;
    const old = nodes.get(alias);
    for (const svc of old.services) if (!node.services.some(s => s.port === svc.port && s.protocol === svc.protocol)) node.services.push(svc);
    for (const tag of old.tags) if (!node.tags.includes(tag)) node.tags.push(tag);
    nodes.delete(alias);
  }
  for (const node of nodes.values()) {
    if (node.deviceType === 'host' && !node.tags.includes('trace-hop') && !node.tags.includes('target'))
      node.tags.push('target');
    if (node.tags.includes('target') && node.status === 'unknown')
      appendNote(node, '扫描目标；尚无已确认的响应。');
  }

  // The initiating host is a separate role from the server emitting probes.
  // HTTP evidence describes a task request, never a physical network cable.
  let originNode = null;
  const localOrigin = isLoopbackAddress(origin?.sourceAddress);
  if (includeOrigin) {
    originNode = {
      id: 'task-origin', displayName: '源主机', ip: localOrigin ? '' : origin?.sourceAddress || '', hostName: '',
      osName: '', osVersion: '', deviceType: 'client', vendor: '',
      status: origin?.sourceAddress ? 'up' : 'unknown', tags: localOrigin ? ['source', 'local-request'] : ['source'], services: [], x: 0, y: 0,
      note: localOrigin
        ? '本机请求：后端收到回环地址 ' + origin.sourceAddress + ' 的连接。回环地址不代表源主机的局域网 IP；本机进程或本地代理都可能产生此连接，无法据此确认物理源主机。'
        : origin?.sourceAddress
        ? '任务发起请求；后端观察到的来源地址：' + origin.sourceAddress
          + '。如经过代理或地址转换，此地址可能是代理出口，不能推断原始设备地址。'
          + '\n记录时间：' + origin.capturedAt
        : '此任务未记录发起端地址；不会用当前查看页面的主机补填历史来源。',
    };
    nodes.set('task-origin', originNode);
    if (origin?.serverAddress) {
      const executors = [...nodes.values()].filter(n => n.deviceType === 'scanner');
      const server = executors.find(n => n.ip === origin.serverAddress)
        || (executors.length === 1 ? executors[0] : nodeFor(origin.serverAddress));
      if (isLoopbackAddress(server.ip)) {
        server.ip = '';
        if (!server.tags.includes('local-server')) server.tags.push('local-server');
      }
      server.displayName = '服务器';
      server.status = 'up';
      if (server.deviceType !== 'scanner') server.deviceType = 'server';
      if (!server.tags.includes('server')) server.tags.push('server');
      appendNote(server, '任务接收地址：' + origin.serverAddress + '；记录时间：' + origin.capturedAt);
      if (origin.sourceAddress) edges.set('task-request', {
        id: 'task-request', sourceId: originNode.id, targetId: server.id,
        type: 'task-request', label: localOrigin ? '本机请求' : '任务请求',
        note: 'HTTP 请求：' + origin.sourceAddress + ' → ' + origin.serverAddress
          + '；记录时间：' + origin.capturedAt + '。这是任务发起关系，不代表物理直连或探测路径。',
      });
    }
  }
  // Logical LAN membership is supported by interface scope + discovery records.
  // It is deliberately distinct from a detected physical switch or forwarding path.
  const lanMembership = new Map();
  for (const row of records.filter(r => r.result_type === 'lan_scope')) {
    const data = dataOf(row), scope = cidrScope(data?.cidr);
    if (!scope || !isIP(data?.serverAddress)) continue;
    const context = records.find(r => r.scan_task_id === row.scan_task_id && r.result_type === 'network_context'
      && dataOf(r)?.interfaces?.some(i => i.device === data.device && i.address === data.serverAddress));
    if (!context) continue;
    const inScope = ip => isIP(ip) === 4 && ((ipv4Number(ip) & scope.mask) >>> 0) === scope.network;
    const members = new Set();
    const server = nodeFor(data.serverAddress);
    server.deviceType = 'scanner'; server.displayName = '服务器'; server.status = 'up';
    for (const tag of ['server','scanner']) if (!server.tags.includes(tag)) server.tags.push(tag);
    if (inScope(server.ip)) members.add(server.id);
    for (const hostRow of records.filter(r => r.scan_task_id === row.scan_task_id && r.result_type === 'lan_host_discovery')) {
      const host = dataOf(hostRow);
      if (host?.scope !== scope.cidr || host.status !== 'up' || !inScope(host.host)) continue;
      const node = nodeFor(host.host);
      node.status = 'up';
      if (!node.tags.includes('lan-host')) node.tags.push('lan-host');
      if (host.hostName) node.hostName = host.hostName;
      if (host.vendor) node.vendor = host.vendor;
      appendNote(node, host.evidence);
      if (host.mac) appendNote(node, 'MAC: ' + host.mac);
      appendNote(node, '局域网主机发现：' + scope.cidr + '，接口 ' + data.device
        + (hostRow.captured_at ? '，采集时间 ' + hostRow.captured_at : ''));
      members.add(node.id);
    }
    // An independently scanned target can also establish membership by response.
    for (const node of nodes.values()) {
      if (node.tags.includes('target') && node.status === 'up' && inScope(node.ip)) members.add(node.id);
    }
    if (originNode?.ip && inScope(originNode.ip)) {
      const discoveredOrigin = nodes.get(hostKey(originNode.ip));
      if (discoveredOrigin && discoveredOrigin !== server && members.has(discoveredOrigin.id)) {
        for (const service of discoveredOrigin.services) {
          const existing = originNode.services.find(s => s.port === service.port && s.protocol === service.protocol);
          if (!existing) originNode.services.push(service);
          else if (existing.state !== 'open') Object.assign(existing, service);
        }
        for (const field of ['hostName','vendor','osName','osVersion']) {
          if (discoveredOrigin[field]) originNode[field] = discoveredOrigin[field];
        }
        originNode.tags = [...new Set([...originNode.tags, ...discoveredOrigin.tags])];
        appendNote(originNode, discoveredOrigin.note);
        for (const edge of edges.values()) {
          if (edge.sourceId === discoveredOrigin.id) edge.sourceId = originNode.id;
          if (edge.targetId === discoveredOrigin.id) edge.targetId = originNode.id;
        }
        nodes.delete(hostKey(originNode.ip));
        members.delete(discoveredOrigin.id); members.add(originNode.id);
      }
    }
    const id = 'lan-' + scope.cidr;
    nodes.set(id, { id, displayName: '虚拟交换机', ip: '', hostName: scope.cidr,
      osName: '', osVersion: '', vendor: '', deviceType: 'network_segment', status: 'unknown',
      tags: ['virtual-switch'], services: [], x: 0, y: 0,
      note: '逻辑分组：' + scope.cidr + '；依据服务器接口 ' + data.device
        + ' 的网段配置及主机响应生成，并非发现的实体交换机，也不代表主机流量经过服务器。'
        + (data.complete ? '' : '\n局域网发现未完成，当前成员可能不完整。') });
    for (const member of members) {
      const edgeId = 'lan:' + id + '>' + member;
      edges.set(edgeId, { id: edgeId, sourceId: id, targetId: member,
        type: 'virtual-link', label: '同网段', note: '属于发现范围 ' + scope.cidr + '；逻辑归属，不代表物理端口或网线连接。' });
      lanMembership.set(member, id);
    }
  }
  const nodeArray = [...nodes.values()];
  const maxHop = Math.max(0, ...nodeArray.filter(n => !n.tags.includes('target'))
    .map(n => hopDepths.get(n.id) || (n.deviceType === 'router' ? 1 : 0)));
  const lanes = new Map();
  for (const node of nodeArray) {
    const lane = node === originNode ? (lanMembership.has(node.id) ? 0 : -1) : node.tags.includes('virtual-switch') ? 1 : lanMembership.has(node.id) && !node.tags.includes('server') ? 2 : node.tags.includes('server') || node.deviceType === 'scanner' ? 0 : node.tags.includes('target') ? maxHop + 1
      : hopDepths.get(node.id) || 1;
    if (!lanes.has(lane)) lanes.set(lane, []);
    lanes.get(lane).push(node);
  }
  for (const [lane, members] of lanes) {
    members.sort((a, b) => a.id.localeCompare(b.id));
    members.forEach((node, row) => {
      node.x = 80 + lane * 360;
      node.y = Math.round((row - (members.length - 1) / 2) * 170);
    });
  }
  const serverCount = nodeArray.filter(n => n.tags.includes('server') || n.deviceType === 'scanner').length;
  const targetCount = nodeArray.filter(n => n.tags.includes('target')).length;
  const hopCount = nodeArray.filter(n => n.deviceType !== 'scanner' && !n.tags.includes('server')
    && !n.tags.includes('source') && !n.tags.includes('target') && !n.tags.includes('lan-host') && n.deviceType !== 'network_segment').length;
  const observed = [...edges.values()].filter(e => e.type === 'route').length;
  const responses = [...edges.values()].filter(e => e.type === 'reachability').length;
  const lanCount = nodeArray.filter(n => n.tags.includes('lan-host')).length;
  const lanWarnings = records.filter(r => r.result_type === 'scan_warning').map(dataOf)
    .filter(d => d?.phase === 'lan-discovery').map(d => d.message);
  if (!records.some(r => r.result_type === 'lan_scope') && !lanWarnings.length) {
    const context = records.find(r => r.result_type === 'network_context');
    if (context) {
      const hosts = records.filter(r => r.scan_task_id === context.scan_task_id && r.result_type === 'host_discovery')
        .map(dataOf).filter(d => d?.host && !d.traceTarget).map(d => d.host);
      const scope = selectLanDiscoveryScope(target, dataOf(context), hosts);
      if (scope.reason) lanWarnings.push(scope.reason);
    }
  }
  return {
    summary: (includeOrigin ? '源主机 ' + (localOrigin ? '本机请求（地址未识别）' : origin?.sourceAddress ? '1' : '地址未记录') + ' · ' : '') + '服务器 ' + serverCount + ' · 目标 ' + targetCount + ' · 响应跳点 ' + hopCount
      + ' · 跳点链路 ' + observed + (responses ? ' · 目标响应 ' + responses + '（路径未确认）' : '')
      + (lanMembership.size ? ' · 局域网响应主机 ' + lanCount + '；虚拟交换机及虚线仅表示同网段。' : '；未响应和缺失跳点不补线。')
      + (lanWarnings.length ? ' ' + [...new Set(lanWarnings)].join('；') : '')
      + (!serverCount ? ' 尚未取得扫描执行端地址。' : ''),
    nodes: nodeArray, edges: [...edges.values()],
  };
}

// AI may enrich descriptions of existing assets. It cannot create topology
// evidence, discard observed hosts/services, or turn response-only edges into paths.
export function mergeTopologyEnhancement(baseline, enhancement) {
  const merged = structuredClone(baseline);
  if (!Array.isArray(enhancement?.nodes)) return merged;
  for (const node of merged.nodes) {
    const candidate = enhancement.nodes.find(n => n && typeof n === 'object' && (
      (n.id === node.id && (!n.ip || !node.ip || hostKey(n.ip) === node.ip)) || (node.ip && hostKey(n.ip) === node.ip)
      || (node.hostName && hostKey(n.hostName) === node.hostName)));
    if (!candidate || node.deviceType === 'network_segment') continue;
    for (const field of ['osName', 'osVersion', 'vendor']) {
      if (!node[field] && typeof candidate[field] === 'string') node[field] = candidate[field].slice(0, 200);
    }
  }
  return merged;
}
