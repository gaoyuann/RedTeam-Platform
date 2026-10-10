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
        evidence: 'Nmap traceroute to ' + host.host + ': ' + line.trim(),
      });
      // Missing TTLs break the path: do not invent direct links across them.
      if (previousHop && previousHop.ttl + 1 === ttl && previousHop.address !== address) {
        emit('network_link', {
          source: previousHop.address, target: address, type: 'route',
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
