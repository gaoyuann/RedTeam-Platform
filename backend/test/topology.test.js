import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapResults, parseNmapInterfaces, topologyScanArgs, normalizeTopologyTarget } from '../src/services/nmapTopology.js';
import { extractTopologyFromResults, mergeTopologyEnhancement } from '../src/services/topologyBuilder.js';

const multiHost = [
  'Nmap scan report for web.local (10.20.16.10)',
  'Host is up (0.003s latency).',
  'PORT STATE SERVICE',
  '22/tcp open ssh OpenSSH 9.0',
  '443/tcp filtered https',
  'MAC Address: 02:00:00:00:00:10 (Example)',
  'TRACEROUTE (using port 80/tcp)',
  'HOP RTT ADDRESS',
  '1 0.20 ms 10.20.16.1',
  '2 0.30 ms 10.20.16.10',
  '',
  'Nmap scan report for db.local (10.20.17.20)',
  'Host is up (0.002s latency).',
  '5432/tcp open postgresql',
  'TRACEROUTE (using port 80/tcp)',
  'HOP RTT ADDRESS',
  '1 0.20 ms 10.20.16.1',
  '2 0.30 ms 10.20.17.20',
  'Nmap done: 4096 IP addresses (2 hosts up)',
].join('\n');

test('Nmap multi-host ports retain ownership and route evidence', () => {
  const results = parseNmapResults(multiHost);
  assert.deepEqual(results.filter(r => r.result_type === 'open_port').map(r => [r.result_data.host, r.result_data.port]),
    [['10.20.16.10',22], ['10.20.16.10',443], ['10.20.17.20',5432]]);
  const topology = extractTopologyFromResults('10.20.16.0/20', results);
  assert.equal(topology.nodes.length, 4);
  const web = topology.nodes.find(n => n.ip === '10.20.16.10');
  const db = topology.nodes.find(n => n.ip === '10.20.17.20');
  assert.equal(web.vendor, 'Example');
  assert.equal(web.services[0].product, 'OpenSSH');
  assert.equal(web.services[0].version, '9.0');
  assert.equal(results.find(r => r.result_type === 'open_port').severity, 'medium');
  assert.deepEqual(web.services.map(s => s.port), ['22','443']);
  assert.deepEqual(db.services.map(s => s.port), ['5432']);
  assert.equal(topology.edges.filter(e => e.type === 'route').length, 2);
  assert.equal(topology.edges.filter(e => e.type === 'virtual-link').length, 3);
  assert.equal(topology.nodes.filter(n => n.deviceType === 'network_segment')[0].displayName, '10.20.16.0/20');
  for (const edge of topology.edges) {
    assert.ok(topology.nodes.some(n => n.id === edge.sourceId));
    assert.ok(topology.nodes.some(n => n.id === edge.targetId));
  }
});

test('missing TTLs do not become direct links; prose is not a port', () => {
  const output = ['Nmap scan report for 192.0.2.10', 'Host is up.',
    'Time 14:28:40, 100% filtered, 2026-10-10', 'TRACEROUTE',
    'HOP RTT ADDRESS', '1 1.0 ms 192.0.2.1', '2 ...', '3 3.0 ms 192.0.2.3',
    '4 4.0 ms 192.0.2.10'].join('\n');
  const records = parseNmapResults(output);
  assert.equal(records.filter(r => r.result_type === 'open_port').length, 0);
  assert.equal(records.filter(r => r.result_type === 'network_link').length, 1);
  assert.equal(records.find(r => r.result_type === 'network_link').result_data.source, '192.0.2.3');
});

test('empty CIDR is a scope, never a live host or an invented gateway', () => {
  const topology = extractTopologyFromResults('10.1.2.0/24', []);
  assert.equal(topology.nodes.length, 1);
  assert.equal(topology.nodes[0].deviceType, 'network_segment');
  assert.equal(topology.nodes[0].status, 'unknown');
  assert.deepEqual(topology.edges, []);
  const single = extractTopologyFromResults('192.0.2.10', []);
  assert.equal(single.nodes[0].status, 'unknown');
  assert.equal(single.nodes.length, 1);
  assert.deepEqual(single.edges, []);
});

test('raw legacy output is recovered; ambiguous hostless ports are not assigned', () => {
  const rows = [
    { scan_task_id: 'old', source_tool: 'nmap', result_type: 'raw_output', result_data: JSON.stringify({output: multiHost}) },
    { scan_task_id: 'old', result_type: 'open_port', result_data: {port: 9999, service: 'unknown'} },
  ];
  const topology = extractTopologyFromResults('10.20.16.0/20', rows);
  assert.equal(topology.nodes.filter(n => n.deviceType !== 'network_segment').length, 3);
  assert.ok(!topology.nodes.some(n => n.services.some(s => s.port === '9999')));
});

test('filtered and -Pn assumed hosts remain unknown', () => {
  const rows = parseNmapResults('Nmap scan report for 192.0.2.10\nHost is up.\n443/tcp filtered https', { assumedUp: true });
  const topology = extractTopologyFromResults('192.0.2.10', rows);
  assert.equal(topology.nodes[0].status, 'unknown');
});

test('legacy records fall back to their own scan target', () => {
  const topology = extractTopologyFromResults('10.0.0.0/24', [
    {scan_task_id:'a', scan_target:'10.0.0.2', result_type:'open_port', result_data:{port:22, state:'open'}},
    {scan_task_id:'b', scan_target:'10.0.0.3', result_type:'open_port', result_data:{port:80, state:'open'}},
  ]);
  assert.equal(topology.nodes.find(n => n.ip === '10.0.0.2').services[0].port, '22');
  assert.equal(topology.nodes.find(n => n.ip === '10.0.0.3').services[0].port, '80');
});

test('same prefixes alone do not invent subnet membership or connections', () => {
  const topology = extractTopologyFromResults('10.0.0.2', [
    {result_type:'host_discovery', result_data:{host:'10.0.0.2',status:'up'}},
    {result_type:'host_discovery', result_data:{host:'10.0.0.3',status:'up'}},
  ]);
  assert.equal(topology.nodes.length, 2);
  assert.equal(topology.edges.length, 0);
});

test('AI omissions and hallucinated links cannot replace evidence', () => {
  const baseline = extractTopologyFromResults('10.20.16.0/20', parseNmapResults(multiHost));
  const enhanced = mergeTopologyEnhancement(baseline, {
    nodes: [{ip:'10.20.16.10', osName:'Linux', services:[]}, {ip:'1.2.3.4'}],
    edges: [{sourceId:'fake',targetId:'fake2'}],
  });
  assert.equal(enhanced.nodes.length, baseline.nodes.length);
  assert.deepEqual(enhanced.edges, baseline.edges);
  assert.equal(enhanced.nodes.find(n => n.ip === '10.20.16.10').osName, 'Linux');
  assert.equal(enhanced.nodes.find(n => n.ip === '10.20.16.10').services.length, 2);
  assert.equal(baseline.nodes.find(n => n.ip === '10.20.16.10').osName, '');
  assert.deepEqual(mergeTopologyEnhancement(baseline, null), baseline);
});

test('topology scanning uses exact scope, discovery and traceroute', () => {
  assert.deepEqual(topologyScanArgs('192.0.2.10'), ['-sn','--traceroute','--reason','192.0.2.10']);
  assert.equal(normalizeTopologyTarget('https://example.test:8443/app'), 'example.test');
  assert.equal(topologyScanArgs('10.0.0.0/20').at(-1), '10.0.0.0/20');
  assert.ok(topologyScanArgs('2001:db8::1').includes('-6'));
  for (const input of ['-iL /etc/passwd','10.0.0.1 10.0.0.2','999.1.1.1','10.0.0.0/33','']) {
    assert.throws(() => topologyScanArgs(input));
  }
});

test('IPv6 route hops keep full addresses', () => {
  const rows = parseNmapResults('Nmap scan report for 2001:db8::10\nHost is up.\nTRACEROUTE\n1 1.0 ms 2001:db8::1\n2 2.0 ms 2001:db8::10');
  const topology = extractTopologyFromResults('2001:db8::10', rows);
  assert.equal(topology.edges.length, 1);
  assert.ok(topology.nodes.some(n => n.ip === '2001:db8::1'));
});

test('repeated observations deduplicate nodes, services and links', () => {
  const rows = parseNmapResults(multiHost);
  const once = extractTopologyFromResults('10.20.16.0/20', rows);
  const twice = extractTopologyFromResults('10.20.16.0/20', [...rows,...rows]);
  assert.deepEqual(twice, once);
});

test('scanner context selects longest-prefix route without inventing a physical gateway', () => {
  const context = parseNmapInterfaces([
    '************************INTERFACES************************',
    'DEV (SHORT) IP/MASK TYPE UP MTU MAC',
    'eth0 (eth0) 10.0.0.5/24 ethernet up 1500 02:00:00:00:00:05',
    'eth1 (eth1) 192.0.2.5/24 ethernet up 1500 02:00:00:00:00:06',
    '**************************ROUTES**************************',
    'DST/MASK DEV METRIC GATEWAY',
    '0.0.0.0/0 eth0 100 10.0.0.1',
    '192.0.2.0/24 eth1 10',
  ].join('\n'));
  assert.equal(context.interfaces.length,2);
  const topology = extractTopologyFromResults('192.0.2.10', [
    ...parseNmapResults('Nmap scan report for 192.0.2.10\nHost is up.'),
    {result_type:'network_context',result_data:context},
  ]);
  assert.equal(topology.nodes.length,2);
  assert.ok(topology.nodes.some(n => n.ip === '192.0.2.5' && n.deviceType === 'scanner'));
  assert.equal(topology.edges.length,1);
  assert.equal(topology.edges[0].label,'路由配置');
  assert.ok(!topology.nodes.some(n => n.ip === '10.0.0.1'));
});

test('default route adds scanner and gateway with unknown reachability', () => {
  const topology = extractTopologyFromResults('203.0.113.10', [
    ...parseNmapResults('Nmap scan report for 203.0.113.10\nHost is up.'),
    {result_type:'network_context',result_data:{
      interfaces:[{device:'eth0',address:'10.0.0.5',prefix:24}],
      routes:[{device:'eth0',destination:'0.0.0.0/0',gateway:'10.0.0.1',metric:100}],
    }},
  ]);
  assert.equal(topology.nodes.find(n => n.ip === '10.0.0.1').status,'unknown');
  assert.equal(topology.edges.length,1);
  assert.ok(!topology.edges.some(e => e.targetId === 'host-203.0.113.10'));
});
