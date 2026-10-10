import { isIP } from 'node:net';

// Parse Nmap's host sections, not arbitrary IPs or numbers in report prose.
export function parseNmapResults(stdout = '', { assumedUp = false } = {}) {
  const results = [];
  let host = null, tracing = false, previousHop = null;
  const emit = (type, data) => results.push({
    result_type: type, result_data: data, source_tool: 'nmap',
    severity: type === 'open_port' && data.state === 'open' ? 'medium' : 'info',
  });
  for (const line of String(stdout).split(/\r?\n/)) {
    const report = line.match(/^Nmap scan report for (.+)$/);
    if (report) {
      const named = report[1].match(/^(.+) \(([^)]+)\)$/);
      const address = named ? named[2] : report[1].trim();
      host = { host: address, hostName: named ? named[1] : '', status: 'unknown' };
      tracing = false;
      previousHop = null;
      continue;
    }
    if (!host) continue;
    if (/^Host is up/.test(line)) {
      host.status = assumedUp || /user-set/i.test(line) ? 'unknown' : 'up';
      host.evidence = line.trim();
      emit('host_discovery', { ...host });
      continue;
    }
    const port = line.match(/^(\d+)\/(tcp|udp)\s+(open\|filtered|closed\|filtered|open|filtered|closed)\s+(.+)/);
    if (port) {
      emit('open_port', { host: host.host, port: Number(port[1]), protocol: port[2], state: port[3], service: port[4].trim() });
      continue;
    }
    const mac = line.match(/^MAC Address: ([\dA-F:]+)(?: \((.*)\))?/i);
    if (mac) emit('host_discovery', { ...host, mac: mac[1], vendor: mac[2] || '' });
    if (/^TRACEROUTE\b/.test(line)) { tracing = true; previousHop = null; continue; }
    if (!tracing) continue;
    const hop = line.match(/^\s*(\d+)\s+[\d.]+\s+ms\s+(.+?)\s*$/);
    if (hop) {
      const address = hop[2].match(/\(([^)]+)\)$/)?.[1] || hop[2];
      if (!isIP(address)) { previousHop = null; continue; }
      const ttl = Number(hop[1]);
      emit('host_discovery', {
        host: address, status: 'up', deviceType: address === host.host ? 'host' : 'router',
        traceTarget: host.host, ttl, rttMs: Number(line.trim().split(/\s+/)[1]),
        evidence: 'Nmap traceroute to ' + host.host + ': ' + line.trim(),
      });
      // Missing TTLs break the path: do not invent direct links across them.
      if (previousHop && previousHop.ttl + 1 === ttl && previousHop.address !== address) {
        emit('network_link', {
          source: previousHop.address, target: address, type: 'route',
          traceTarget: host.host, sourceTtl: previousHop.ttl, targetTtl: ttl,
          evidence: 'Nmap traceroute to ' + host.host + ', TTL ' + previousHop.ttl + ' → ' + ttl,
        });
      }
      previousHop = { address, ttl };
    } else if (/^\s*\d+/.test(line)) {
      previousHop = null;
    } else if (line.trim() && !/^HOP\s+RTT/.test(line)) {
      tracing = false;
    }
  }
  return results;
}

export function normalizeTopologyTarget(value) {
  let target = String(value || '').trim();
  if (/^https?:\/\//i.test(target)) {
    try { target = new URL(target).hostname.replace(/^\[|\]$/g, ''); }
    catch { throw new Error('无效的目标地址'); }
  }
  // Never expand a single target to a guessed /24.
  if (isIP(target)) return target;
  const cidr = target.match(/^(.+)\/(\d{1,2})$/);
  if (cidr && isIP(cidr[1]) === 4 && Number(cidr[2]) <= 32) return target;
  if (/^(?=.{1,253}$)[a-z\d](?:[a-z\d.-]*[a-z\d])?$/i.test(target)
      && !/^[\d.]+$/.test(target)
      && target.split('.').every(label => label.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label))) return target;
  throw new Error('拓扑探测目标需为一个 IP、主机名或 IPv4 CIDR 网段');
}

export function topologyScanArgs(target) {
  const value = normalizeTopologyTarget(target);
  return ['-sn', '--traceroute', '--reason', ...(isIP(value) === 6 ? ['-6'] : []), value];
}

export function parseNmapInterfaces(stdout = '') {
  const interfaces = [], routes = [];
  let section = '';
  for (const line of String(stdout).split(/\r?\n/)) {
    if (/INTERFACES/.test(line)) { section = 'interfaces'; continue; }
    if (/ROUTES/.test(line)) { section = 'routes'; continue; }
    if (section === 'interfaces') {
      const match = line.match(/^(\S+)\s+\(([^)]+)\)\s+(\S+)\/(\d+)\s+\S+\s+(\S+)/);
      if (match && isIP(match[3]) === 4 && Number(match[4]) <= 32 && match[5] === 'up') {
        interfaces.push({ device: match[1], address: match[3], prefix: Number(match[4]) });
      }
    } else if (section === 'routes') {
      const match = line.match(/^(\S+)\/(\d+)\s+(\S+)\s+(\d+)(?:\s+(\S+))?/);
      if (match && isIP(match[1]) === 4 && Number(match[2]) <= 32) {
        routes.push({ destination: match[1] + '/' + match[2], device: match[3],
          metric: Number(match[4]), gateway: isIP(match[5] || '') === 4 ? match[5] : '' });
      }
    }
  }
  return { interfaces, routes };
}

// Select only the directly connected IPv4 LAN used to reach this target.
// A routed destination must never expand discovery onto an unrelated LAN.
export function selectLanDiscoveryScope(target, context, resolvedHosts = []) {
  let value;
  try { value = normalizeTopologyTarget(String(target).replace(/^([^/:]+):\d+$/, '$1')); } catch { return { reason: '目标地址无法用于局域网发现' }; }
  const number = ip => ip.split('.').reduce((n, part) => ((n << 8) | Number(part)) >>> 0, 0);
  const scopeOf = value => {
    const [ip, bits] = value.split('/');
    const prefix = Number(bits);
    if (isIP(ip) !== 4 || bits === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (number(ip) & mask) >>> 0;
    return { prefix, mask, network, cidr: [24,16,8,0].map(n => (network >>> n) & 255).join('.') + '/' + prefix };
  };
  const requested = value.includes('/') ? scopeOf(value) : null;
  const addresses = isIP(value) === 4 ? [value] : requested ? [value.split('/')[0]] : resolvedHosts.filter(ip => isIP(ip) === 4);
  let routedReason = '';
  for (const address of addresses) {
    const route = (context?.routes || []).map(r => ({...r, scope: scopeOf(r.destination)}))
      .filter(r => r.scope && ((number(address) & r.scope.mask) >>> 0) === r.scope.network)
      .sort((a,b) => b.scope.prefix - a.scope.prefix || a.metric - b.metric)[0];
    if (!route) continue;
    if (route.gateway && route.gateway !== '0.0.0.0') {
      const outgoing = (context.interfaces || []).find(i => i.device === route.device);
      routedReason = '未执行局域网发现：扫描端 ' + (outgoing?.address || route.device)
        + ' 通过网关 ' + route.gateway + ' 访问目标 ' + address
        + '，未处于目标直连网段。当前仅展示探测路径；请在目标局域网内的服务器上运行扫描。';
      continue;
    }
    const iface = (context.interfaces || []).find(i => {
      const subnet = scopeOf(i.address + '/' + i.prefix);
      return i.device === route.device && !i.address.startsWith('127.') && subnet
        && ((number(address) & subnet.mask) >>> 0) === subnet.network;
    });
    if (!iface) continue;
    const subnet = scopeOf(iface.address + '/' + iface.prefix);
    if (requested && requested.prefix < subnet.prefix) continue;
    const scope = requested || subnet;
    // Bound automatic discovery; never silently substitute a guessed /24.
    if (scope.prefix < 20) return { reason: '局域网范围 ' + scope.cidr + ' 超过自动发现上限 4096 个地址，请填写更小的目标网段' };
    return { cidr: scope.cidr, serverAddress: iface.address, device: iface.device };
  }
  return { reason: routedReason || '未确认目标与服务器处于同一直连 IPv4 网段，未扩展局域网发现' };
}
