import { isIP } from 'node:net';
import { parseNmapResults } from './nmapTopology.js';

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

export function extractTopologyFromResults(target, results) {
  const nodes = new Map(), edges = new Map(), scopes = new Map();
  const addScope = value => {
    const scope = cidrScope(value);
    if (scope) scopes.set(scope.cidr, scope);
  };
  addScope(target);
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
    addScope(row.scan_target);
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
    if (data?.host && row.result_type !== 'network_link') {
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

  // Select the most specific route from the same scan's execution context.
  // These edges describe configured forwarding, not a verified physical cable.
  for (const row of records.filter(r => r.result_type === 'network_context')) {
    const data = dataOf(row);
    if (!Array.isArray(data?.interfaces) || !Array.isArray(data?.routes)) continue;
    const scanHosts = knownHostsByScan.get(row.scan_task_id) || new Set();
    for (const key of scanHosts) {
      const dest = nodes.get(key);
      if (!dest || isIP(dest.ip) !== 4 || dest.status !== 'up') continue;
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
      if (!iface || iface.address === dest.ip) continue;
      const source = nodeFor(iface.address);
      source.deviceType = 'scanner';
      source.status = 'up';
      source.displayName = '扫描源 ' + iface.address;
      if (!source.tags.includes('scanner')) source.tags.push('scanner');
      appendNote(source, 'Nmap --iflist：扫描执行环境接口 ' + iface.device);
      const next = nodeFor(route.gateway && route.gateway !== '0.0.0.0' ? route.gateway : dest.ip);
      if (!next || source.id === next.id) continue;
      if (next.ip !== dest.ip && next.deviceType === 'host') next.deviceType = 'router';
      const id = 'configured:' + source.id + '>' + next.id;
      edges.set(id, {
        id, sourceId: source.id, targetId: next.id, label: '路由配置', type: 'route',
        note: 'Nmap --iflist：' + route.destination + ' 经 ' + route.device
          + (route.gateway ? ' 下一跳 ' + route.gateway : ' 直连')
          + '；表示扫描环境的转发配置，不代表物理布线或下一跳已响应。',
      });
    }
  }

  // Replace a hostname placeholder with its resolved IP when Nmap supplies it.
  for (const node of [...nodes.values()]) {
    const alias = hostKey(node.hostName);
    if (!node.ip || !alias || alias === node.ip || !nodes.has(alias)) continue;
    const old = nodes.get(alias);
    for (const svc of old.services) if (!node.services.some(s => s.port === svc.port && s.protocol === svc.protocol)) node.services.push(svc);
    nodes.delete(alias);
  }
  if (!nodes.size && !scopes.size) {
    const placeholder = nodeFor(target);
    if (placeholder) placeholder.note = '扫描目标；尚无已确认的主机响应。';
  }

  // Explicit scope membership is logical, not inferred physical switching.
  for (const scope of scopes.values()) {
    const id = 'network-' + scope.cidr;
    const members = [...nodes.values()].filter(n => isIP(n.ip) === 4
      && ((ipv4Number(n.ip) & scope.mask) >>> 0) === scope.network);
    nodes.set(id, {
      id, displayName: scope.cidr, ip: '', hostName: '', osName: '', osVersion: '',
      deviceType: 'network_segment', vendor: '', status: 'unknown',
      note: '用户指定的探测范围；虚线仅表示地址归属，不代表同一二层网络或真实交换机。',
      tags: ['logical'], x: 0, y: 0, services: [],
    });
    for (const member of members) {
      const edgeId = 'scope:' + id + '>' + member.id;
      edges.set(edgeId, { id: edgeId, sourceId: id, targetId: member.id,
        label: '范围归属（逻辑）', type: 'virtual-link', note: '依据明确的 CIDR ' + scope.cidr + ' 分组，未经物理链路验证。' });
    }
  }
  const nodeArray = [...nodes.values()];
  // Platform-specific left-to-right asset lanes. Shared routers remain one
  // node, so observed routes can branch without a ring of synthetic switches.
  const lanes = [[], [], [], []];
  for (const node of nodeArray) {
    const lane = node.deviceType === 'scanner' ? 0
      : node.deviceType === 'router' ? 1 : node.deviceType === 'network_segment' ? 3 : 2;
    lanes[lane].push(node);
  }
  lanes.forEach((members, lane) => {
    members.sort((a, b) => a.id.localeCompare(b.id));
    members.forEach((node, row) => {
      node.x = 80 + lane * 360;
      node.y = Math.round((row - (members.length - 1) / 2) * 150);
    });
  });
  const hostCount = nodeArray.filter(n => n.deviceType !== 'network_segment').length;
  const observed = [...edges.values()].filter(e => e.type === 'route').length;
  return {
    summary: hostCount + ' 个主机/跳点，' + observed + ' 条路由关系，' + (edges.size - observed)
      + ' 条逻辑归属；未响应不等于不存在。',
    nodes: nodeArray, edges: [...edges.values()],
  };
}

// AI may enrich descriptions of existing assets. It cannot create topology
// evidence, discard observed hosts/services, or upgrade logical edges to routes.
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
