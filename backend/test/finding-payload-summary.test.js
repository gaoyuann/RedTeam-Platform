import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'node:url';
import { runMigrations } from '../src/db/migrate.js';
import { scanPage } from '../src/services/scanResultQuery.js';
import { findingPayloadCodeSummaries } from '../src/services/findingPayloadCodeSummary.js';
import express from 'express';
import http from 'node:http';
import scanRoutes from '../src/routes/scans.js';
import resultRoutes from '../src/routes/taskResults.js';

test('task finding payload summary keeps matching separate from saved code and does not expose code', async t => {
  const db = new Database(':memory:'); t.after(() => db.close());
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role) VALUES('payload_owner','fixture','user')").run();
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES('p','http://fixture.invalid','completed','payload_owner','s','{}'),('q','http://fixture.invalid','completed','payload_owner','s','{}')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES('s','http://fixture.invalid','web_scan','COMPLETED','payload_owner','p')").run();
  const add = db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity) VALUES('s','web_vuln',?,?)");
  const finding = Number(add.run('{"title":"Missing X-Frame-Options header"}', 'high').lastInsertRowid);
  const info = Number(add.run('{"title":"An observation"}', 'info').lastInsertRowid);
  const pipeline = db.prepare("SELECT * FROM pipelines WHERE pipeline_id='p'").get();
  const record = () => scanPage(db, pipeline).scan_records.find(row => row.id === finding);
  assert.equal(record().payload_code.state, 'missing');
  assert.equal(db.prepare('SELECT count(*) n FROM finding_verifications').get().n, 0, 'listing never creates a verification');
  db.prepare("INSERT INTO finding_verifications(id,pipeline_id,finding_id,scan_task_id) VALUES('v','p',?,'s'),('other','q',?,'s')").run(finding, finding);
  const generation = db.prepare("INSERT INTO finding_verification_code(id,verification_id,request_id,input_hash,input_data,state,result,created_by) VALUES(?,?,?,'fixture','{}',?,?,'payload_owner')");
  const result = JSON.stringify({files:[{filename:'repro.py',source:'private fixture source'}]});
  generation.run('foreign','other','foreign', 'ready', result);
  assert.equal(record().payload_code.state, 'missing', 'another task sharing the finding cannot supply code');
  generation.run('ready','v','ready', 'ready', result);
  assert.equal(record().payload_match.status, 'none');
  assert.deepEqual(record().payload_code, {schema_version:1,state:'available',scan_count:0,generated_count:1,latest_generation_state:'ready'});
  generation.run('retry','v','retry', 'error', null);
  assert.equal(record().payload_code.state, 'available', 'failed retry keeps the previous successful code');
  assert.equal(record().payload_code.latest_generation_state, 'error');
  db.prepare(`INSERT INTO finding_payload_collections(id,verification_id,flow_id,request_marker,state,source_fingerprint,scripts,created_by,created_at,updated_at)
    VALUES('collection','v','1','fixture-marker','ready','fixture',?,'payload_owner','fixture','fixture')`)
    .run(JSON.stringify([{id:'s',content:'private original script'}, {content:''}]));
  assert.equal(record().payload_code.scan_count, 1);
  db.prepare("INSERT INTO users(username,password,role) VALUES('payload_outsider','fixture','user')").run();
  const app=express();
  app.use((req,res,next)=>{req.user={sub:req.headers['x-user'] || 'payload_owner',role:'user'};next();});
  app.use('/scans',scanRoutes(db));app.use('/pipelines/:id/results',resultRoutes(db));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  const base='http://127.0.0.1:'+server.address().port;
  const scan=await (await fetch(base+'/scans/s')).json();
  assert.deepEqual(scan.data.results.find(row=>row.id===finding).payload_code,record().payload_code,'single scan and task list show identical code metadata');
  assert.equal((await fetch(base+'/pipelines/p/results?view=scans',{headers:{'x-user':'payload_outsider'}})).status,403);
  assert.equal((await fetch(base+'/scans/s',{headers:{'x-user':'payload_outsider'}})).status,403,'another owner cannot read a scan or its payload metadata');
  const page = scanPage(db, pipeline);
  assert.equal(page.scan_records.find(row => row.id === info).payload_code, null);
  assert.ok(!JSON.stringify(page).includes('private fixture source') && !JSON.stringify(page).includes('private original script'));
  assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n, 0);
  assert.deepEqual(scanPage(db,pipeline,{limit:1,after:finding}).scan_records.map(row=>row.id), [info]);
  db.prepare("DELETE FROM finding_verification_code WHERE id='ready'").run();
  db.prepare("UPDATE finding_payload_collections SET scripts='not json'").run();
  assert.equal(record().payload_code.state, 'error', 'malformed historical JSON does not break listing');
  for (const state of ['generating', 'needs_information', 'interrupted']) {
    db.prepare("UPDATE finding_verification_code SET state=? WHERE id='retry'").run(state);
    assert.equal(record().payload_code.state, state);
  }
  generation.run('invalid','v','invalid','ready','{"files":["legacy text",null,{"source":""}]}');
  assert.equal(record().payload_code.generated_count, 0);
});

test('legacy databases report unavailable metadata without inventing missing code', () => {
  const db = new Database(':memory:');
  try {
    assert.equal(findingPayloadCodeSummaries(db,'p',[1]).get(1).state,'unavailable');
    assert.equal(findingPayloadCodeSummaries(db,'p',[1]).get(1).generated_count,null);
    assert.equal(findingPayloadCodeSummaries(db,'p',[]).size,0);
  } finally { db.close(); }
});
