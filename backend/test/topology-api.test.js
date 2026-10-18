import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'node:url';
import { runMigrations } from '../src/db/migrate.js';
import topologyRoutes from '../src/routes/topology.js';
import scanRoutes from '../src/routes/scans.js';
import pipelineRoutes from '../src/routes/pipelines.js';
import { captureTopologyOrigin } from '../src/services/topologyOrigin.js';

async function fixture(t) {
  const db = new Database(':memory:');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  for (const username of ['alice', 'bob'])
    db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)').run(username, 'test', 'user');
  const app = express();
  app.use(express.json(), (req, res, next) => {
    const sub=req.headers['x-user'] || 'alice';
    req.user = { role: sub==='admin'?'admin':'user', sub }; next();
  });
  app.use('/topology', topologyRoutes(db));
  app.use('/scans', scanRoutes(db));
  app.use('/pipelines', pipelineRoutes(db));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); });
  const base = 'http://127.0.0.1:' + server.address().port;
  const request = async (path, body, user = 'alice', method) => {
    const result = await fetch(base + path, {
      method: method || (body ? 'POST' : 'GET'), headers: {'Content-Type':'application/json', 'x-user':user},
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: result.status, body: await result.json() };
  };
  return { db, request };
}

test('task topology aggregates only its scans, retaining route evidence', async t => {
  const {db,request} = await fixture(t);
  db.prepare('INSERT INTO pipelines (pipeline_id,target,scan_task_id,created_by) VALUES (?,?,?,?)').run('p1','10.0.0.0/24','old','alice');
  db.prepare('INSERT INTO pipelines (pipeline_id,target,scan_task_id,created_by) VALUES (?,?,?,?)').run('p2','10.1.0.0/24','','bob');
  const insertTask = db.prepare('INSERT INTO scan_tasks (scan_task_id,target,scan_type,parameters,status,created_by) VALUES (?,?,?,?,?,?)');
  insertTask.run('old','10.0.0.0/24','port_scan',null,'COMPLETED','alice');
  insertTask.run('discovery','10.0.0.0/24','topology_scan',JSON.stringify({pipeline_id:'p1'}),'COMPLETED','alice');
  insertTask.run('other','10.1.0.0/24','topology_scan',JSON.stringify({pipeline_id:'p2'}),'COMPLETED','bob');
  const insert = db.prepare('INSERT INTO scan_results (scan_task_id,result_type,result_data,source_tool,captured_at) VALUES (?,?,?,?,?)');
  insert.run('old','open_port',JSON.stringify({host:'10.0.0.2',port:22, state:'open'}),'nmap','1');
  insert.run('discovery','host_discovery',JSON.stringify({host:'10.0.0.3',status:'up'}),'nmap','2');
  insert.run('discovery','network_link',JSON.stringify({source:'10.0.0.2',target:'10.0.0.3',type:'route',evidence:'TTL 1 → 2'}),'nmap','3');
  insert.run('other','host_discovery',JSON.stringify({host:'10.1.0.99',status:'up'}),'nmap','4');
  const result = await request('/topology/from-pipeline/p1');
  assert.equal(result.status,200);
  const graph = result.body.data.topology;
  assert.ok(graph.nodes.some(n => n.ip === '10.0.0.2' && n.services[0].port === '22'));
  assert.ok(graph.nodes.some(n => n.ip === '10.0.0.3'));
  assert.ok(!graph.nodes.some(n => n.ip === '10.1.0.99'));
  assert.equal(graph.edges.filter(e => e.type === 'route').length,1);
  assert.equal((await request('/topology/from-pipeline/p1',null,'bob')).status,403);
});

test('task-attached discovery validates ownership and exact target scope', async t => {
  const {db,request} = await fixture(t);
  db.prepare('INSERT INTO pipelines (pipeline_id,target,scan_task_id,created_by) VALUES (?,?,?,?)').run('p1','https://example.test:8443/','','alice');
  const created = await request('/scans',{target:'https://example.test:8443/', scan_type:'topology_scan',parameters:{pipeline_id:'p1',extra_args:'-Pn'}});
  assert.equal(created.status,201);
  assert.equal(created.body.data.target,'example.test');
  assert.deepEqual(JSON.parse(created.body.data.parameters),{pipeline_id:'p1',timeout:300});
  assert.equal(created.body.data.created_by,'alice');
  const administered=await request('/scans',{target:'example.test',scan_type:'topology_scan',parameters:{pipeline_id:'p1'}},'admin');
  assert.equal(administered.status,201);assert.equal(administered.body.data.created_by,'alice');
  db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(administered.body.data.scan_task_id);
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'host_discovery',?)")
    .run(administered.body.data.scan_task_id,JSON.stringify({host:'example.test',status:'up'}));
  const graph=(await request('/topology/from-pipeline/p1')).body.data.topology;
  assert.equal(graph.nodes.find(node=>node.hostName==='example.test').status,'up');
  assert.ok(graph.metadata.scanIds.includes(administered.body.data.scan_task_id));
  assert.equal((await request('/scans',{target:'example.test',scan_type:'topology_scan',parameters:{pipeline_id:'p1'}},'bob')).status,403);
  assert.equal((await request('/scans',{target:'10.0.0.0/24',scan_type:'topology_scan',parameters:{pipeline_id:'p1'}})).status,400);
  assert.equal((await request('/scans',{target:'-iL /tmp/list',scan_type:'topology_scan'})).status,400);
});

test('completed topology scan generates deterministic graph without AI', async t => {
  const {db,request} = await fixture(t);
  db.prepare('INSERT INTO scan_tasks (scan_task_id,target,scan_type,status,created_by) VALUES (?,?,?,?,?)')
    .run('d1','10.0.0.0/24','topology_scan','COMPLETED','alice');
  db.prepare('INSERT INTO scan_results (scan_task_id,result_type,result_data,source_tool,captured_at) VALUES (?,?,?,?,?)')
    .run('d1','host_discovery',JSON.stringify({host:'10.0.0.2',status:'up'}),'nmap','1');
  const result = await request('/topology/generate-from-scan',{scan_task_id:'d1'});
  assert.equal(result.status,200);
  assert.equal(result.body.data.topology.nodes.length,1);
  assert.deepEqual(result.body.data.topology.edges,[]);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status) VALUES ('unowned','192.0.2.8','port_scan','COMPLETED')").run();
  assert.equal((await request('/topology/generate-from-scan',{scan_task_id:'unowned'})).status,403);
});

test('pipeline records socket origin, preserves it on config edits and projects source plus server', async t => {
  const {db,request} = await fixture(t);
  const created = await request('/pipelines',{target:'203.0.113.10',config:{
    topology_origin:{sourceAddress:'203.0.113.99',serverAddress:'203.0.113.98',transport:'http-request'},
  }});
  assert.equal(created.status,201);
  const pipelineId = created.body.data.pipeline_id;
  const origin = created.body.data.config.topology_origin;
  assert.equal(origin.sourceAddress,'127.0.0.1');
  assert.equal(origin.serverAddress,'127.0.0.1');
  const edited = await request('/pipelines/'+pipelineId,{config:{timeout:45}},'alice','PUT');
  assert.equal(edited.status,200);
  const saved = JSON.parse(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(pipelineId).config);
  assert.deepEqual(saved.topology_origin,origin);
  const graph = (await request('/topology/from-pipeline/'+pipelineId)).body.data.topology;
  assert.equal(graph.nodes.find(n => n.tags.includes('source')).displayName,'源主机');
  assert.equal(graph.nodes.find(n => n.tags.includes('server')).displayName,'服务器');
  assert.equal(graph.edges[0].type,'task-request');
});

test('origin ignores untrusted forwarded addresses and normalizes mapped IPv4', () => {
  const origin = captureTopologyOrigin({socket:{remoteAddress:'::ffff:192.0.2.5',localAddress:'::ffff:192.0.2.10'},
    headers:{'x-forwarded-for':'203.0.113.99'}});
  assert.equal(origin.sourceAddress,'192.0.2.5');
  assert.equal(origin.serverAddress,'192.0.2.10');
});

test('partial source audits project HTTP and TCP entry evidence without inventing routes or leaking source', async t => {
  const {db,request}=await fixture(t);
  const origin={sourceAddress:'192.0.2.20',serverAddress:'192.0.2.10',transport:'http-request',capturedAt:'fixture'};
  for (const [suffix,target] of [['http','http://192.0.2.30:8089/'],['tcp','tcp://192.0.2.30:8091']]) {
    const pid='source-'+suffix, sid='scan-'+suffix;
    db.prepare('INSERT INTO pipelines(pipeline_id,target,scan_task_id,config,created_by) VALUES (?,?,?,?,?)')
      .run(pid,target,sid,JSON.stringify({scan_mode:'source_assisted',topology_origin:origin}),'alice');
    db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by) VALUES (?,?,'source_scan','PARTIAL','alice')").run(sid,target);
    const insert=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES (?,?,?,?)');
    insert.run(sid,'application_observation',JSON.stringify({url:target,connected:true,response:'private response'}),'target-request');
    insert.run(sid,'application_observation',JSON.stringify({url:'http://192.0.2.99:8089/',connected:true}),'target-request');
    insert.run(sid,'source_finding',JSON.stringify({title:'Input bounds candidate',file:'input.c',code:'private source code'}),'source-ai');
    const response=await request('/topology/from-pipeline/'+pid);
    assert.equal(response.status,200);
    const graph=response.body.data.topology;
    const node=graph.nodes.find(node=>node.ip==='192.0.2.30');
    assert.equal(node.status,'up');assert.equal(node.services[0].state,'open');
    assert.equal(node.services[0].port,suffix==='http'?'8089':'8091');
    assert.equal(graph.nodes.some(node=>node.ip==='192.0.2.99'),false);
    assert.equal(graph.edges.filter(edge=>edge.type==='route').length,0);
    assert.equal(graph.edges.filter(edge=>edge.type==='application-request').length,1);
    assert.equal(graph.edges.find(edge=>edge.type==='application-request').provenance.sources.length,1,
      'edge evidence excludes observations outside the runtime endpoint');
    assert.equal(graph.risks[0].status,'candidate');assert.equal(graph.metadata.projectionVersion,4);
    assert.ok(!JSON.stringify(graph).includes('private source code'));
    assert.ok(!JSON.stringify(graph).includes('private response'));
    assert.equal((await request('/topology/generate-from-scan',{scan_task_id:sid},'bob')).status,403);
    assert.equal((await request('/topology/generate-from-scan',{scan_task_id:sid})).status,200);
  }
});

test('node scans use server-side assets, task scope and idempotent identities', async t => {
  const {db,request}=await fixture(t);
  const config={task_scope:{includes:['10.2.0.0/24'],excludes:['10.2.0.99'],execution_location:'scanner'}};
  db.prepare("INSERT INTO pipelines(pipeline_id,target,config,created_by) VALUES ('nodes','10.2.0.10',?,'alice')")
    .run(JSON.stringify(config));
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id,parameters) VALUES ('seed','10.2.0.10','topology_scan','COMPLETED','alice','nodes',?)")
    .run(JSON.stringify({pipeline_id:'nodes'}));
  const insert=db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES ('seed','host_discovery',?,'nmap')");
  insert.run(JSON.stringify({host:'10.2.0.10',status:'up'}));
  insert.run(JSON.stringify({host:'10.2.0.11',status:'up'}));
  insert.run(JSON.stringify({host:'10.2.0.99',status:'up'}));
  db.prepare("INSERT INTO task_assets(asset_id,pipeline_id,host,state) VALUES ('asset_a','nodes','10.2.0.10','reachable'),('asset_b','nodes','10.2.0.99','out_of_scope'),('asset_c','nodes','10.2.0.20','unknown')").run();
  db.prepare("INSERT INTO task_services(service_id,pipeline_id,asset_id,port,protocol,name,state) VALUES ('service_c','nodes','asset_c',8080,'tcp','http','unverified')").run();
  db.prepare("INSERT INTO task_entries(entry_id,pipeline_id,service_id,kind,value,state) VALUES ('entry_c','nodes','service_c','web_url','http://10.2.0.20:8080/','declared')").run();
  db.prepare("INSERT INTO task_checks(check_id,pipeline_id,service_id,entry_id,check_type,state,reason,created_at,updated_at) VALUES ('check_c','nodes','service_c','entry_c','web_security','not_checked','缺少条件','1','1')").run();
  const graph=(await request('/topology/from-pipeline/nodes')).body.data.topology;
  const allowed=graph.nodes.find(node=>node.ip==='10.2.0.10');
  const excluded=graph.nodes.find(node=>node.ip==='10.2.0.99');
  assert.equal(allowed.assetId,'asset_a');assert.equal(allowed.scan.eligible,true);
  assert.equal(excluded.scan.eligible,false);
  const observed=graph.nodes.find(node=>node.ip==='10.2.0.11');
  assert.equal(observed.assetId,null);
  assert.equal(observed.scan.eligible,true);
  const inventory=graph.nodes.find(node=>node.ip==='10.2.0.20');
  assert.equal(inventory.assetId,'asset_c');
  assert.equal(inventory.services[0].state,'unverified');
  assert.equal(inventory.entries[0].entryId,'entry_c');
  assert.equal(inventory.checks[0].state,'not_checked');
  assert.equal(graph.edges.some(edge=>edge.sourceId===inventory.id || edge.targetId===inventory.id),false);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES ('primary','10.2.0.10','port_scan','PENDING','alice','nodes')").run();
  const body={node_id:allowed.id,scan_type:'port_scan',request_id:'node_scan_0001'};
  const created=await request('/topology/from-pipeline/nodes/node-scans',body);
  assert.equal(created.status,201);
  assert.equal(created.body.data.target,'10.2.0.10');
  const scanId=created.body.data.scan_task_id;
  assert.equal((await request('/topology/from-pipeline/nodes/node-scans',body)).body.data.scan_task_id,scanId);
  assert.equal((await request('/topology/from-pipeline/nodes/node-scans',{...body,request_id:'node_scan_0002'})).body.data.scan_task_id,scanId);
  assert.equal((await request('/topology/from-pipeline/nodes/node-scans',{...body,node_id:excluded.id,request_id:'node_scan_0003'})).status,403);
  assert.equal((await request('/topology/from-pipeline/nodes/node-scans',{...body,request_id:'node_scan_0004'},'bob')).status,403);
  assert.equal((await request('/topology/from-pipeline/nodes/node-scans',{...body,node_id:'manual-fake',request_id:'node_scan_0005'})).status,409);
  db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(scanId);
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES (?,'open_port',?,'nmap')")
    .run(scanId,JSON.stringify({host:'10.2.0.10',port:443,protocol:'tcp',state:'open',service:'https'}));
  const updated=(await request('/topology/from-pipeline/nodes')).body.data.topology;
  assert.ok(updated.nodes.find(node=>node.ip==='10.2.0.10').services.some(service=>service.port==='443'));
  assert.equal((await request('/topology/from-pipeline/nodes/node-scans',{...body,request_id:'node_scan_0006'})).status,201);
  assert.equal((await request('/topology/generate-from-scan',{scan_task_id:scanId},'bob')).status,403);
});

test('logical LAN edges cite only their own observed scope', async t => {
  const {db,request}=await fixture(t);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,config,created_by) VALUES ('multi','10.2.0.10',?,'alice')")
    .run(JSON.stringify({task_scope:{includes:['10.2.0.0/24','10.3.0.0/24']}}));
  const addScan=db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id,parameters) VALUES (?,?,'topology_scan','COMPLETED','alice','multi',?)");
  const addResult=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES (?,?,?,?)');
  const scopeIds=new Map();
  for (const [scanId,cidr,server,host,device] of [
    ['scan-a','10.2.0.0/24','10.2.0.5','10.2.0.10','ethA'],
    ['scan-b','10.3.0.0/24','10.3.0.5','10.3.0.10','ethB'],
  ]) {
    addScan.run(scanId,host,JSON.stringify({pipeline_id:'multi'}));
    addResult.run(scanId,'network_context',JSON.stringify({interfaces:[{device,address:server,prefix:24}],
      routes:[{destination:cidr,device,metric:0,gateway:''}]}),'nmap');
    const scopeRow=addResult.run(scanId,'lan_scope',JSON.stringify({cidr,serverAddress:server,device,complete:true}),'nmap');
    scopeIds.set(cidr,Number(scopeRow.lastInsertRowid));
    addResult.run(scanId,'lan_host_discovery',JSON.stringify({host,status:'up',scope:cidr}),'nmap');
  }
  const response=await request('/topology/from-pipeline/multi');
  assert.equal(response.status,200);
  const graph=response.body.data.topology;
  const segments=new Map(graph.nodes.filter(node=>node.deviceType==='network_segment')
    .map(node=>[node.id,node.hostName]));
  assert.equal(segments.size,2);
  for(const node of graph.nodes.filter(item=>item.deviceType==='network_segment')) {
    assert.equal(node.provenance.kind,'inferred');
    assert.deepEqual(node.provenance.sources.map(source=>source.result_id),[scopeIds.get(node.hostName)]);
  }
  const membership=graph.edges.filter(edge=>edge.type==='virtual-link');
  assert.ok(membership.length>=4);
  for(const edge of membership) {
    const cidr=segments.get(edge.sourceId);
    assert.ok(cidr);
    assert.deepEqual(edge.provenance.sources.map(source=>source.result_id),[scopeIds.get(cidr)]);
    assert.equal(edge.provenance.kind,'inferred');
  }
});

test('reachability edges retain the scanner that observed each response', async t => {
  const {db,request}=await fixture(t);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,created_by) VALUES ('vantages','10.2.0.10','alice')").run();
  const addScan=db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES (?,'10.2.0.10','port_scan','COMPLETED','alice','vantages')");
  const addResult=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES (?,?,?,?)');
  const responseIds=new Map();
  for (const [scanId,address,device,gateway] of [
    ['local','10.2.0.5','ethA',''],
    ['routed','10.3.0.5','ethB','10.3.0.1'],
  ]) {
    addScan.run(scanId);
    addResult.run(scanId,'network_context',JSON.stringify({interfaces:[{device,address,prefix:24}],
      routes:[{destination:'10.2.0.0/24',device,metric:0,gateway}]}),'nmap');
    const response=addResult.run(scanId,'open_port',JSON.stringify({host:'10.2.0.10',port:80,
      protocol:'tcp',state:'open',evidence:`response from ${address}`}),'nmap');
    responseIds.set(address,Number(response.lastInsertRowid));
  }
  const response=await request('/topology/from-pipeline/vantages');
  assert.equal(response.status,200);
  const graph=response.body.data.topology;
  const hosts=new Map(graph.nodes.map(node=>[node.id,node.ip]));
  const edges=graph.edges.filter(edge=>edge.type==='reachability');
  assert.equal(edges.length,2);
  for(const edge of edges)
    assert.deepEqual(edge.provenance.sources.map(source=>source.result_id),[responseIds.get(hosts.get(edge.sourceId))]);
});

test('task topology excludes another owner discovery even when it references this task', async t => {
  const {db,request}=await fixture(t);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,created_by) VALUES ('scope','192.0.2.1','alice')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,parameters,created_by) VALUES ('foreign','192.0.2.1','topology_scan','COMPLETED',?,'bob')")
    .run(JSON.stringify({pipeline_id:'scope'}));
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('foreign','host_discovery',?)")
    .run(JSON.stringify({host:'192.0.2.99',status:'up'}));
  const graph=(await request('/topology/from-pipeline/scope')).body.data.topology;
  assert.equal(graph.nodes.some(node=>node.ip==='192.0.2.99'),false);
});

test('source-only task retains independent network evidence and never interprets source files as runtime',async t=>{
  const {db,request}=await fixture(t),source='http://192.0.2.40:18090/code/';
  db.prepare("INSERT INTO pipelines(pipeline_id,target,scan_task_id,created_by,config) VALUES ('network-only',?,'files','alice',?)")
    .run(source,JSON.stringify({scan_mode:'source_assisted',input_kind:'source',source_url:source}));
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,parameters) VALUES ('files',?,'source_scan','PARTIAL','alice',?)")
    .run(source,JSON.stringify({input_kind:'source',source_url:source}));
  const insert=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,?,?)');
  insert.run('files','application_observation',JSON.stringify({url:source,connected:true}));
  insert.run('files','source_finding',JSON.stringify({title:'Static candidate',file:'input.c'}));
  for(const [id,target,owner] of [['network','192.0.2.40','alice'],['foreign-host','192.0.2.99','alice'],['foreign-owner','192.0.2.40','bob']]) {
    db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,parameters) VALUES (?,?,'topology_scan','COMPLETED',?,?)")
      .run(id,target,owner,JSON.stringify({pipeline_id:'network-only'}));
    insert.run(id,'host_discovery',JSON.stringify({host:target,status:'up'}));
    insert.run(id,'open_port',JSON.stringify({host:target,port:22,protocol:'tcp',state:'open',service:'ssh'}));
  }
  const graph=(await request('/topology/from-pipeline/network-only')).body.data.topology;
  const node=graph.nodes.find(node=>node.ip==='192.0.2.40');
  assert.equal(node.status,'up');assert.deepEqual(node.services.map(service=>String(service.port)),['22']);
  assert.equal(graph.nodes.some(node=>node.ip==='192.0.2.99'),false);
  assert.deepEqual(graph.risks,[]);assert.equal(graph.edges.some(edge=>edge.type==='application-request'),false);
  assert.ok(!JSON.stringify(graph).includes('foreign-owner'));
  assert.match(graph.summary,/网络探测独立于程序执行/);
});

test('source directory input is not projected as a running program and an explicit runtime stays separate',async t=>{
  const {db,request}=await fixture(t),source='http://192.0.2.40:18090/code/',runtime='tcp://192.0.2.30:8091';
  db.prepare("INSERT INTO pipelines(pipeline_id,target,scan_task_id,created_by,config) VALUES ('code-only',?,'code-scan','alice',?)")
    .run(source,JSON.stringify({scan_mode:'program_dynamic',input_kind:'source'}));
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,parameters) VALUES ('code-scan',?,'program_scan','PARTIAL','alice',?)")
    .run(source,JSON.stringify({input_kind:'source'}));
  let graph=(await request('/topology/from-pipeline/code-only')).body.data.topology;
  assert.equal(graph.nodes.find(node=>node.ip==='192.0.2.40').status,'unknown');
  assert.deepEqual(graph.nodes.find(node=>node.ip==='192.0.2.40').services,[]);
  assert.match(graph.summary,/网络探测独立于程序执行/);
  const direct=await request('/topology/generate-from-scan',{scan_task_id:'code-scan'});
  assert.equal(direct.status,200);assert.equal(direct.body.data.topology.nodes.find(node=>node.ip==='192.0.2.40').status,'unknown');
  assert.deepEqual(direct.body.data.topology.nodes.find(node=>node.ip==='192.0.2.40').services,[]);
  db.prepare("UPDATE pipelines SET config=? WHERE pipeline_id='code-only'")
    .run(JSON.stringify({scan_mode:'program_dynamic',input_kind:'source',runtime_target:runtime}));
  db.prepare("UPDATE scan_tasks SET parameters=? WHERE scan_task_id='code-scan'")
    .run(JSON.stringify({input_kind:'source',runtime_target:runtime}));
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('code-scan','application_observation',?)")
    .run(JSON.stringify({url:runtime,connected:true}));
  graph=(await request('/topology/from-pipeline/code-only')).body.data.topology;
  assert.equal(graph.nodes.some(node=>node.ip==='192.0.2.40'),false);
  assert.equal(graph.nodes.find(node=>node.ip==='192.0.2.30').status,'up');
});
