import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import express from 'express';
import http from 'node:http';
import migrateLinks from '../src/db/migrations/032_finding_payload_links.js';
import { bindFindingPayload, findingPayloadMatches, findingPayloadSummary, matchPayloads } from '../src/services/findingPayloads.js';
import { getPayloadIndex, refreshPayloadIndex } from '../src/services/payloadLoader.js';
import { scanPage } from '../src/services/scanResultQuery.js';
import taskResultsRoutes from '../src/routes/taskResults.js';

function fixture() {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE users(username TEXT PRIMARY KEY, role TEXT, is_active INTEGER);
    INSERT INTO users VALUES ('alice','user',1),('bob','user',1),('admin','admin',1);
    CREATE TABLE pipelines(pipeline_id TEXT PRIMARY KEY,target TEXT,created_by TEXT,status TEXT,scan_task_id TEXT,config TEXT);
    INSERT INTO pipelines VALUES ('p','http://fixture.invalid','alice','completed','s','{}'),
      ('q','http://fixture.invalid','bob','completed','other','{}');
    CREATE TABLE pipeline_steps(id INTEGER PRIMARY KEY,pipeline_id TEXT,step_order INTEGER,step_type TEXT,input_data TEXT,output_data TEXT);
    CREATE TABLE scan_tasks(id INTEGER PRIMARY KEY,scan_task_id TEXT UNIQUE,pipeline_id TEXT,target TEXT,scan_type TEXT,created_by TEXT,status TEXT, retry_of_scan_task_id TEXT,error_message TEXT);
    INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,created_by,status,retry_of_scan_task_id,error_message)
      VALUES ('s','p','http://fixture.invalid','web_scan','alice','COMPLETED',NULL,NULL),
      ('other','q','http://fixture.invalid','web_scan','bob','COMPLETED',NULL,NULL);
    CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT REFERENCES scan_tasks(scan_task_id),result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);
    CREATE TABLE generated_payloads(payload_id TEXT PRIMARY KEY,payload_type TEXT,payload_data TEXT,import_status TEXT);
  `);
  migrateLinks(db);
  const add = db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity) VALUES (?,?,?,?)');
  const sql = Number(add.run('s','sql_injection',JSON.stringify({finding:'Boolean-based SQL injection at parameter id; MySQL backend'}),'high').lastInsertRowid);
  const header = Number(add.run('s','web_vuln',JSON.stringify({finding:'Missing X-Frame-Options header'}),'medium').lastInsertRowid);
  const negative = Number(add.run('s','web_vuln',JSON.stringify({finding:'SQL injection not vulnerable'}),'high').lastInsertRowid);
  const info = Number(add.run('s','web_vuln',JSON.stringify({finding:'SQL injection parameter id'}),'info').lastInsertRowid);
  const other = Number(add.run('other','sql_injection',JSON.stringify({finding:'SQL injection at id'}),'high').lastInsertRowid);
  return { db, sql, header, negative, info, other };
}

test('specific vulnerability matching preserves unmatched and information records', () => {
  const { db, sql, header, negative, info } = fixture();
  try {
    const row = id => db.prepare('SELECT * FROM scan_results WHERE id=?').get(id);
    const matches = matchPayloads(db, row(sql));
    assert.ok(matches.some(match => match.payload_id === 'sqli-mysql-basic'));
    assert.ok(matches.every(match => match.version.startsWith('sha256:') && match.match_basis && match.consumption));
    assert.equal(matches.find(match => match.payload_id === 'sqli-mysql-basic').availability, 'available');
    assert.deepEqual(matchPayloads(db, row(header)), []);
    assert.deepEqual(matchPayloads(db, row(negative)), []);
    assert.deepEqual(matchPayloads(db, row(info)), []);
    assert.equal(findingPayloadSummary(db, row(header)).status, 'none');
    assert.equal(findingPayloadSummary(db, row(info)), null);
    const sqlmap = { result_type:'sql_injection', severity:'critical',
      result_data:JSON.stringify({detail:'Target is vulnerable to SQL injection',technique:'boolean-based blind',dbms:'MySQL'}) };
    assert.equal(matchPayloads(db, sqlmap)[0].payload_id,'sqli-mysql-basic');
    const nuclei = { result_type:'vulnerability',severity:'critical',
      result_data:JSON.stringify({template:'CVE-2021-44228',info:{name:'Log4j RCE',classification:{'cve-id':['CVE-2021-44228']}}}) };
    assert.equal(matchPayloads(db,nuclei)[0].payload_id,'log4j-rce');
    const reflected = { result_type:'web_vuln',severity:'high',
      result_data:JSON.stringify({finding:'Reflected XSS in query parameter'}) };
    assert.equal(matchPayloads(db,reflected)[0].payload_id,'xss-reflected');
    assert.ok(matchPayloads(db,reflected).every(match => !['xss-beef','xss-cookie-theft','xss-keylogger'].includes(match.payload_id)));
    const ssrf = { result_type:'web_vuln',severity:'high',
      result_data:JSON.stringify({finding:'Server-side request forgery in url parameter'}) };
    assert.deepEqual(matchPayloads(db,ssrf).map(match => match.payload_id),['ssrf-basic']);
    const command = { result_type:'web_vuln',severity:'high',
      result_data:JSON.stringify({finding:'Command injection in ping endpoint'}) };
    assert.deepEqual(matchPayloads(db,command).map(match => match.payload_id),['rce-command-injection']);
    const nosql = { result_type:'web_vuln',severity:'high',
      result_data:JSON.stringify({finding:'NoSQL injection in MongoDB query'}) };
    assert.deepEqual(matchPayloads(db,nosql).map(match => match.payload_id),['sqli-mongodb-basic']);
    const deserialize = { result_type:'web_vuln',severity:'high',
      result_data:JSON.stringify({finding:'PHP unserialize remote code execution'}) };
    assert.equal(matchPayloads(db,deserialize)[0].payload_id,'rce-deserialize-php');
    assert.equal(scanPage(db, db.prepare("SELECT * FROM pipelines WHERE pipeline_id='p'").get()).scan_records.length, 4);
  } finally { db.close(); }
});

test('association is idempotent, keeps old versions, and never crosses databases', () => {
  const { db, sql, header } = fixture();
  const second = fixture().db;
  try {
    const row = db.prepare('SELECT * FROM scan_results WHERE id=?').get(sql);
    const candidate = matchPayloads(db, row).find(match => match.payload_id === 'sqli-mysql-basic');
    assert.ok(candidate);
    bindFindingPayload(db, row, candidate.payload_id, candidate.version, 'alice');
    bindFindingPayload(db, row, candidate.payload_id, candidate.version, 'alice');
    assert.equal(db.prepare('SELECT count(*) AS n FROM finding_payload_links').get().n, 1);
    assert.equal(findingPayloadSummary(db, row).status, 'linked');
    assert.throws(() => bindFindingPayload(db, row, candidate.payload_id, 'sha256:old', 'alice'), error => error.status === 409);
    assert.throws(() => bindFindingPayload(db, db.prepare('SELECT * FROM scan_results WHERE id=?').get(header), candidate.payload_id, candidate.version, 'alice'), error => error.status === 400);
    const generated = { id:'ai_sqli_fixture', name:'Fixture SQL check', tags:['sqli'], execution:[{command:'fixture'}] };
    db.prepare('INSERT INTO generated_payloads VALUES (?,?,?,?)').run(generated.id,'web',JSON.stringify(generated),'accepted');
    assert.ok(getPayloadIndex(db)[generated.id]);
    assert.equal(getPayloadIndex(second)[generated.id], undefined);
    const firstVersion = matchPayloads(db,row).find(match => match.payload_id === generated.id).version;
    bindFindingPayload(db,row,generated.id,firstVersion,'alice');
    db.prepare('UPDATE generated_payloads SET payload_data=? WHERE payload_id=?')
      .run(JSON.stringify({...generated,execution:[{command:'fixture-v2'}]}),generated.id);
    const newVersion = matchPayloads(db,row).find(match => match.payload_id === generated.id).version;
    assert.notEqual(newVersion, firstVersion);
    assert.equal(findingPayloadMatches(db,row).links.find(link => link.payload_id === generated.id).availability,'changed');
    bindFindingPayload(db,row,generated.id,newVersion,'alice');
    const links = findingPayloadMatches(db,row).links.filter(link => link.payload_id === generated.id);
    assert.deepEqual(links.map(link => link.active),[true,false]);
    assert.equal(db.prepare('SELECT count(*) AS n FROM finding_payload_links WHERE payload_id=?').get(generated.id).n,2);
  } finally { db.close(); second.close(); refreshPayloadIndex(); }
});

test('task-scoped API enforces ownership, stable result ID and current payload version', async () => {
  const { db, sql, other } = fixture();
  const app = express();
  app.use(express.json(), (req, _res, next) => {
    const sub = req.headers['x-user'] || 'alice';
    req.user = { sub, role: sub === 'admin' ? 'admin' : 'user' };
    next();
  });
  app.use('/pipelines/:id/results', taskResultsRoutes(db));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({status:'error',error:{message:error.message}}));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const url = `http://127.0.0.1:${server.address().port}/pipelines/p/results`;
  try {
    const page = await (await fetch(url+'?view=scans')).json();
    assert.equal(page.data.scan_records.find(record => record.id === sql).payload_match.status,'candidate');
    const detail = await (await fetch(`${url}/records/${sql}/payload-matches`)).json();
    const candidate = detail.data.matches.find(match => match.payload_id === 'sqli-mysql-basic');
    assert.ok(candidate);
    const post = (id, payload, user='alice') => fetch(`${url}/records/${id}/payload-links`, {
      method:'POST', headers:{'content-type':'application/json','x-user':user},body:JSON.stringify(payload),
    });
    assert.equal((await post(sql,{payload_id:candidate.payload_id,version:candidate.version},'bob')).status,403);
    assert.equal((await post(other,{payload_id:candidate.payload_id,version:candidate.version})).status,404);
    assert.equal((await post(sql,{payload_id:candidate.payload_id,version:'sha256:stale'})).status,409);
    assert.equal((await post(sql,{payload_id:'missing',version:candidate.version})).status,404);
    assert.equal((await post(sql,{payload_id:candidate.payload_id,version:candidate.version})).status,200);
    assert.equal((await (await fetch(url+'?view=scans')).json()).data.scan_records.find(record => record.id === sql).payload_match.status,'linked');
    assert.equal((await fetch(`${url}/records/${other}/payload-matches`)).status,404);
    assert.equal((await fetch(`${url}/records/invalid/payload-matches`)).status,400);
    assert.equal((await fetch(`${url}/records/${sql}/payload-matches`,{headers:{'x-user':'bob'}})).status,403);
  } finally { await new Promise(resolve => server.close(resolve)); db.close(); }
});
