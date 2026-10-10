import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import topologyRoutes from '../src/routes/topology.js';
import scanRoutes from '../src/routes/scans.js';
import pipelineRoutes from '../src/routes/pipelines.js';
import { captureTopologyOrigin } from '../src/services/topologyOrigin.js';

async function fixture(t) {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE pipelines (pipeline_id TEXT, target TEXT, scan_task_id TEXT, created_by TEXT, config TEXT, status TEXT, created_at TEXT, updated_at TEXT);'
    + "CREATE TABLE scan_tasks (scan_task_id TEXT, target TEXT, scan_type TEXT, target_class TEXT, parameters TEXT, created_by TEXT, created_at TEXT, status TEXT DEFAULT 'PENDING');"
    + 'CREATE TABLE scan_results (scan_task_id TEXT, result_type TEXT, result_data TEXT, source_tool TEXT, captured_at TEXT);');
  const app = express();
  app.use(express.json(), (req, res, next) => {
    req.user = { role: 'user', sub: req.headers['x-user'] || 'alice' }; next();
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
  const insertTask = db.prepare('INSERT INTO scan_tasks (scan_task_id,target,scan_type,parameters,status) VALUES (?,?,?,?,?)');
  insertTask.run('old','10.0.0.2','port_scan',null,'COMPLETED');
  insertTask.run('discovery','10.0.0.0/24','topology_scan',JSON.stringify({pipeline_id:'p1'}),'COMPLETED');
  insertTask.run('other','10.1.0.0/24','topology_scan',JSON.stringify({pipeline_id:'p2'}),'COMPLETED');
  const insert = db.prepare('INSERT INTO scan_results VALUES (?,?,?,?,?)');
  insert.run('old','open_port',JSON.stringify({port:22, state:'open'}),'nmap','1');
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
  assert.equal((await request('/scans',{target:'example.test',scan_type:'topology_scan',parameters:{pipeline_id:'p1'}},'bob')).status,403);
  assert.equal((await request('/scans',{target:'10.0.0.0/24',scan_type:'topology_scan',parameters:{pipeline_id:'p1'}})).status,400);
  assert.equal((await request('/scans',{target:'-iL /tmp/list',scan_type:'topology_scan'})).status,400);
});

test('completed topology scan generates deterministic graph without AI', async t => {
  const {db,request} = await fixture(t);
  db.prepare('INSERT INTO scan_tasks (scan_task_id,target,scan_type,status) VALUES (?,?,?,?)')
    .run('d1','10.0.0.0/24','topology_scan','COMPLETED');
  db.prepare('INSERT INTO scan_results VALUES (?,?,?,?,?)')
    .run('d1','host_discovery',JSON.stringify({host:'10.0.0.2',status:'up'}),'nmap','1');
  const result = await request('/topology/generate-from-scan',{scan_task_id:'d1'});
  assert.equal(result.status,200);
  assert.equal(result.body.data.topology.nodes.length,1);
  assert.deepEqual(result.body.data.topology.edges,[]);
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
