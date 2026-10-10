import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapResults, parseNmapInterfaces, topologyScanArgs, normalizeTopologyTarget, selectLanDiscoveryScope } from '../src/services/nmapTopology.js';
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
  assert.equal(topology.nodes.length, 3);
  const web = topology.nodes.find(n => n.ip === '10.20.16.10');
  const db = topology.nodes.find(n => n.ip === '10.20.17.20');
  assert.equal(web.vendor, 'Example');
  assert.equal(web.services[0].product, 'OpenSSH');
  assert.equal(web.services[0].version, '9.0');
  assert.equal(results.find(r => r.result_type === 'open_port').severity, 'medium');
  assert.deepEqual(web.services.map(s => s.port), ['22','443']);
  assert.deepEqual(db.services.map(s => s.port), ['5432']);
  assert.equal(topology.edges.filter(e => e.type === 'route').length, 2);
  assert.equal(topology.edges.filter(e => e.type === 'virtual-link').length, 0);
  assert.ok(!topology.nodes.some(n => n.deviceType === 'network_segment'));
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

test('empty CIDR never creates a scope device, live host or invented gateway', () => {
  const topology = extractTopologyFromResults('10.1.2.0/24', []);
  assert.equal(topology.nodes.length, 0);
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
  assert.equal(topology.edges[0].type,'reachability');
  assert.match(topology.summary, /路径未确认/);
  assert.ok(!topology.nodes.some(n => n.ip === '10.0.0.1'));
});

test('default route identifies the server without adding an unobserved gateway', () => {
  const topology = extractTopologyFromResults('203.0.113.10', [
    ...parseNmapResults('Nmap scan report for 203.0.113.10\nHost is up.'),
    {result_type:'network_context',result_data:{
      interfaces:[{device:'eth0',address:'10.0.0.5',prefix:24}],
      routes:[{device:'eth0',destination:'0.0.0.0/0',gateway:'10.0.0.1',metric:100}],
    }},
  ]);
  assert.ok(!topology.nodes.some(n => n.ip === '10.0.0.1'));
  assert.equal(topology.edges.length,1);
  assert.equal(topology.edges[0].type,'reachability');
  assert.match(topology.edges[0].note, /不表示物理直连/);
});

const serverContext = (scanId = 'trace') => ({scan_task_id:scanId, result_type:'network_context',result_data:{
  interfaces:[{device:'eth0',address:'10.0.0.5',prefix:24}],
  routes:[{device:'eth0',destination:'0.0.0.0/0',gateway:'10.0.0.1',metric:100}],
}});
const pathRows = (lines, scanId = 'trace') => parseNmapResults([
  'Nmap scan report for 203.0.113.10', 'Host is up.', '80/tcp open http',
  'TRACEROUTE', 'HOP RTT ADDRESS', ...lines,
].join('\n'), {assumedUp:true}).map(r => ({...r, scan_task_id:scanId}));

test('server, observed hops and target form an ordered path without synthetic nodes', () => {
  const topology = extractTopologyFromResults('203.0.113.10', [
    ...pathRows(['1 0.2 ms 10.0.0.1','2 0.8 ms 198.51.100.1','3 1.0 ms 203.0.113.10']),
    serverContext(),
  ]);
  const ordered = [...topology.nodes].sort((a,b) => a.x-b.x);
  assert.deepEqual(ordered.map(n => n.ip), ['10.0.0.5','10.0.0.1','198.51.100.1','203.0.113.10']);
  assert.equal(ordered[0].displayName,'服务器');
  assert.ok(ordered.at(-1).tags.includes('target'));
  assert.equal(topology.edges.length,3);
  assert.ok(topology.edges.every(e => e.type === 'route'));
  for (let i=0;i<3;i++) assert.ok(topology.edges.some(e => e.sourceId === ordered[i].id && e.targetId === ordered[i+1].id));
});

test('missing first or middle hop never becomes a configured or cross-gap edge', () => {
  const graph = extractTopologyFromResults('203.0.113.10', [
    ...pathRows(['1 ...','2 0.8 ms 198.51.100.1','3 ...','4 1.0 ms 203.0.113.10']), serverContext(),
  ]);
  assert.equal(graph.nodes.length,3);
  assert.equal(graph.edges.length,0);
  assert.ok(!graph.nodes.some(n => n.ip === '10.0.0.1'));
});

test('unresponsive target still displays server and target, with no invented link', () => {
  const graph = extractTopologyFromResults('203.0.113.10', [serverContext()]);
  assert.equal(graph.nodes.length,2);
  assert.equal(graph.nodes.find(n => n.ip === '203.0.113.10').status,'unknown');
  assert.equal(graph.edges.length,0);
});

test('first hop evidence is isolated to its originating scan', () => {
  const graph = extractTopologyFromResults('203.0.113.10', [
    ...pathRows(['1 0.2 ms 10.0.0.1','2 1.0 ms 203.0.113.10'], 'other'), serverContext(),
  ]);
  assert.ok(!graph.edges.some(e => e.sourceId === 'host-10.0.0.5'));
});

test('server scanning itself is one node, not a self link', () => {
  const graph = extractTopologyFromResults('10.0.0.5', [serverContext()]);
  assert.equal(graph.nodes.length,1);
  assert.equal(graph.nodes[0].deviceType,'scanner');
  assert.ok(graph.nodes[0].tags.includes('target'));
  assert.equal(graph.edges.length,0);
});

test('hostname target resolves without a duplicate placeholder', () => {
  const graph = extractTopologyFromResults('https://web.local:80', [
    ...parseNmapResults('Nmap scan report for web.local (203.0.113.10)\nHost is up.\n80/tcp open http'),
    {...serverContext(), scan_task_id:undefined},
  ]);
  assert.equal(graph.nodes.length,2);
  assert.ok(!graph.nodes.some(n => n.id === 'host-web.local'));
  assert.ok(graph.nodes.find(n => n.ip === '203.0.113.10').tags.includes('target'));
});

test('initiator and scan server are distinct roles joined only by request evidence', () => {
  const origin = {sourceAddress:'192.0.2.20',serverAddress:'10.0.0.5',capturedAt:'2026-10-10T01:00:00Z'};
  const graph = extractTopologyFromResults('203.0.113.10', [
    ...pathRows(['1 0.2 ms 10.0.0.1','2 1.0 ms 203.0.113.10']), serverContext(),
  ], {includeOrigin:true,origin});
  const source = graph.nodes.find(n => n.tags.includes('source'));
  const server = graph.nodes.find(n => n.tags.includes('server'));
  assert.equal(source.ip,origin.sourceAddress);
  assert.equal(source.displayName,'源主机');
  assert.equal(server.displayName,'服务器');
  assert.ok(!server.tags.includes('source'));
  assert.ok(source.x < server.x);
  assert.equal(graph.edges.find(e => e.type === 'task-request').targetId,server.id);
  assert.equal(graph.edges.filter(e => e.type === 'route').length,2);
  assert.ok(!graph.edges.some(e => e.sourceId === source.id && e.type === 'route'));
});

test('historical source is explicitly unknown, never replaced with the viewer', () => {
  const graph = extractTopologyFromResults('203.0.113.10', [serverContext()], {includeOrigin:true});
  const source = graph.nodes.find(n => n.tags.includes('source'));
  assert.equal(source.ip,'');
  assert.equal(source.status,'unknown');
  assert.ok(!graph.edges.some(e => e.type === 'task-request'));
});


test('LAN discovery selects actual target interface and mask, never unrelated or routed networks', () => {
  const context = { interfaces: [
    {device:'eth0',address:'10.0.0.5',prefix:24},
    {device:'eth1',address:'192.168.2.130',prefix:25},
  ], routes: [
    {destination:'0.0.0.0/0',device:'eth0',gateway:'10.0.0.1',metric:0},
    {destination:'10.0.0.0/24',device:'eth0',gateway:'',metric:0},
    {destination:'192.168.2.128/25',device:'eth1',gateway:'',metric:0},
  ] };
  const expected = {cidr:'192.168.2.128/25',serverAddress:'192.168.2.130',device:'eth1'};
  assert.deepEqual(selectLanDiscoveryScope('http://192.168.2.150:4280',context),expected);
  assert.deepEqual(selectLanDiscoveryScope('192.168.2.150:4280',context),expected);
  assert.deepEqual(selectLanDiscoveryScope('app.local',context,['192.168.2.150']),expected);
  assert.equal(selectLanDiscoveryScope('192.168.2.160/28',context).cidr,'192.168.2.160/28');
  for (const target of ['203.0.113.1','192.168.2.0/24','::1','app.local'])
    assert.ok(!selectLanDiscoveryScope(target,context).cidr);
  assert.ok(!selectLanDiscoveryScope('10.1.2.3', {interfaces:[{device:'eth0',address:'10.1.2.4',prefix:8}],
    routes:[{destination:'10.0.0.0/8',device:'eth0',gateway:'',metric:0}]}).cidr);
  // A more-specific route through a gateway overrides an overlapping interface subnet.
  context.routes.push({destination:'192.168.2.150/32',device:'eth0',gateway:'10.0.0.1',metric:0});
  assert.ok(!selectLanDiscoveryScope('192.168.2.150',context).cidr);
});

test('LAN graph groups only discovered members and deduplicates source without inventing a physical switch', () => {
  const rows = [
    {result_type:'network_context',result_data:{interfaces:[{device:'eth0',address:'192.168.1.5',prefix:24}],
      routes:[{destination:'192.168.1.0/24',device:'eth0',metric:0,gateway:''}]}},
    {result_type:'lan_scope',result_data:{cidr:'192.168.1.0/24',device:'eth0',serverAddress:'192.168.1.5',complete:true}},
    ...['192.168.1.20','192.168.1.111','192.168.1.30','192.168.2.10'].map(host => ({result_type:'lan_host_discovery',
      result_data:{host,status:'up',scope:'192.168.1.0/24',evidence:'Host is up (arp-response).'}})),
  ].map(r => ({...r,scan_task_id:'lan'}));
  const graph = extractTopologyFromResults('192.168.1.111',rows,{includeOrigin:true,
    origin:{sourceAddress:'192.168.1.20',serverAddress:'192.168.1.5',capturedAt:'now'}});
  assert.equal(graph.nodes.length,5);
  const hub = graph.nodes.find(n => n.deviceType === 'network_segment');
  assert.equal(hub.displayName,'虚拟交换机');
  assert.equal(hub.status,'unknown');
  assert.ok(hub.note.includes('并非发现的实体交换机'));
  assert.equal(graph.edges.filter(e => e.type === 'virtual-link').length,4);
  assert.equal(graph.edges.filter(e => e.type === 'route').length,0);
  assert.equal(graph.nodes.filter(n => n.ip === '192.168.1.20').length,1);
  assert.equal(graph.nodes.find(n => n.ip === '192.168.1.30').tags.includes('target'),false);
  assert.equal(graph.nodes.find(n => n.ip === '192.168.1.111').tags.includes('target'),true);
  assert.ok(!graph.nodes.some(n => n.ip === '192.168.2.10'));
  for (const e of graph.edges) for (const id of [e.sourceId,e.targetId]) assert.ok(graph.nodes.some(n => n.id === id));
  const incomplete = extractTopologyFromResults('192.168.1.111',[...rows,
    {result_type:'scan_warning',result_data:{phase:'lan-discovery',message:'局域网发现未完成'}}]);
  assert.ok(incomplete.summary.includes('局域网发现未完成'));
});


test('loopback request never claims the initiator LAN address or creates a LAN switch across WSL routing', () => {
  const context = {interfaces:[{device:'eth0',address:'172.23.255.129',prefix:20}], routes:[
    {destination:'172.23.240.0/20',device:'eth0',metric:0,gateway:''},
    {destination:'0.0.0.0/0',device:'eth0',metric:0,gateway:'172.23.240.1'},
  ]};
  for (const sourceAddress of ['127.0.0.1','127.0.1.1','::1','::ffff:127.0.0.1']) {
    const graph = extractTopologyFromResults('192.168.1.111',[
      {result_type:'network_context',scan_task_id:'wsl',result_data:context},
    ],{includeOrigin:true,origin:{sourceAddress,serverAddress:'127.0.0.1',capturedAt:'now'}});
    const source = graph.nodes.find(n => n.tags.includes('source'));
    assert.equal(source.ip,'');
    assert.ok(source.tags.includes('local-request'));
    assert.ok(source.note.includes(sourceAddress));
    assert.equal(graph.nodes.find(n => n.tags.includes('server')).ip,'172.23.255.129');
    assert.equal(graph.edges.find(e => e.type === 'task-request').label,'本机请求');
    assert.ok(!graph.nodes.some(n => n.deviceType === 'network_segment'));
    assert.ok(graph.summary.includes('未执行局域网发现'));
    assert.ok(graph.summary.includes('172.23.240.1'));
    assert.ok(graph.summary.includes('地址未识别'));
  }
  const empty = extractTopologyFromResults('192.168.1.111',[],{includeOrigin:true,
    origin:{sourceAddress:'127.0.0.1',serverAddress:'127.0.0.1',capturedAt:'now'}});
  assert.ok(empty.nodes.every(n => n.ip !== '127.0.0.1'));
});


test('repeated LAN discovery preserves source-target services and unique edges', () => {
  const rows = ['first','second'].flatMap(scan_task_id => [
    {scan_task_id,result_type:'network_context',result_data:{interfaces:[{device:'eth0',address:'192.168.1.5',prefix:24}],
      routes:[{destination:'192.168.1.0/24',device:'eth0',metric:0,gateway:''}]}},
    {scan_task_id,result_type:'lan_scope',result_data:{cidr:'192.168.1.0/24',device:'eth0',serverAddress:'192.168.1.5',complete:true}},
    {scan_task_id,result_type:'lan_host_discovery',result_data:{host:'192.168.1.20',scope:'192.168.1.0/24',status:'up',evidence:'ARP response'}},
  ]);
  rows.push({scan_task_id:'first',result_type:'open_port',result_data:{host:'192.168.1.20',port:22,protocol:'tcp',state:'open',service:'ssh'}});
  const graph = extractTopologyFromResults('192.168.1.20',rows,{includeOrigin:true,
    origin:{sourceAddress:'192.168.1.20',serverAddress:'192.168.1.5',capturedAt:'now'}});
  const source = graph.nodes.find(n => n.tags.includes('source'));
  assert.equal(source.services.length,1);
  assert.equal(source.services[0].port,'22');
  assert.ok(source.tags.includes('target'));
  assert.equal(graph.nodes.filter(n => n.ip === source.ip).length,1);
  assert.equal(new Set(graph.edges.map(e => e.type + ':' + e.sourceId + '>' + e.targetId)).size,graph.edges.length);
  for (const edge of graph.edges) for (const id of [edge.sourceId,edge.targetId]) assert.ok(graph.nodes.some(n => n.id === id));
});
