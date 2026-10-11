import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import scanRoutes from '../src/routes/scans.js';
import playbookRoutes from '../src/routes/playbooks.js';
import runRoutes from '../src/routes/runs.js';
async function fixture(t) {
  const db=new Database(':memory:');
  db.exec("CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,target TEXT,scan_type TEXT,target_class TEXT,parameters TEXT,created_by TEXT,created_at TEXT,status TEXT DEFAULT 'PENDING'); CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,captured_at TEXT); CREATE TABLE source_verifications(id INTEGER PRIMARY KEY,finding_id INTEGER,status TEXT,note TEXT,run_id TEXT,reviewed_by TEXT,created_at TEXT); CREATE TABLE playbooks(playbook_id TEXT PRIMARY KEY,metadata TEXT); CREATE TABLE execution_runs(run_id TEXT PRIMARY KEY,playbook_id TEXT);");
  const app=express();
  app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user']||'alice',role:'user'};next();});
  app.use('/scans',scanRoutes(db));app.use('/runs',runRoutes(db));app.use('/playbooks',playbookRoutes(db));
  const server=app.listen(0,'127.0.0.1');
  await new Promise(r=>server.once('listening',r));
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));db.close();});
  const base='http://127.0.0.1:'+server.address().port;
  async function request(path,body,user='alice',method) {
    const response=await fetch(base+path,{method:method||(body?'POST':'GET'),headers:{'content-type':'application/json','x-user':user},...(body?{body:JSON.stringify(body)}:{})});
    return {status:response.status,body:await response.json()};
  }
  return {db,request};
}
test('source API creates runtime targets, isolates source tasks and preserves completed evidence',async t=>{
  const {db,request}=await fixture(t);
  const created=await request('/scans',{target:'tcp://192.168.1.113:8091',scan_type:'source_scan',created_by:'bob'});
  assert.equal(created.status,201);
  const task=created.body.data;
  assert.equal(task.created_by,'alice');assert.equal(task.target_class,'tcp_service');
  assert.equal((await request('/scans/'+task.scan_task_id,null,'bob')).status,403);
  assert.equal((await request('/scans',null,'bob')).body.data.length,0);
  for(const suffix of ['/execute','/abort','/generate-playbook']) assert.equal((await request('/scans/'+task.scan_task_id+suffix,{},'bob')).status,403);
  assert.equal((await request('/scans/'+task.scan_task_id,null,'bob','DELETE')).status,403);
  db.prepare("UPDATE scan_tasks SET status='COMPLETED'").run();
  assert.equal((await request('/scans/'+task.scan_task_id+'/execute',{})).status,409);
  assert.equal((await request('/scans',{target:'exploit-demo',scan_type:'source_scan'})).status,400);
  assert.equal((await request('/scans',{target:'http://192.168.1.113:8090',scan_type:'source_scan',parameters:{connection_id:'nonexistent-project'}})).status,400);
});
test('run creation cannot retarget or use someone else source verification',async t=>{
  const {db,request}=await fixture(t),target='tcp://192.168.1.113:8091';
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,created_by) VALUES ('s','source_scan',?,'alice')").run(target);
  db.prepare("INSERT INTO playbooks VALUES ('p',?)").run(JSON.stringify({source_verification:{scan_task_id:'s',target,finding_ids:[1]}}));
  assert.equal((await request('/runs',{playbook_id:'p',target:'tcp://192.168.1.113:8092'})).status,400);
  assert.equal((await request('/runs',{playbook_id:'p',target},'bob')).status,403);
});

test('source code context and execution evidence are not exposed through other users playbooks or runs',async t=>{
  const {db,request}=await fixture(t),target='http://192.168.1.113:8090/';
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,created_by) VALUES ('s','source_scan',?,'alice')").run(target);
  db.prepare("INSERT INTO playbooks VALUES ('p',?)").run(JSON.stringify({source_verification:{scan_task_id:'s',target,context:[{code:'private source'}]}}));
  db.prepare("INSERT INTO execution_runs VALUES ('r','p')").run();
  assert.equal((await request('/playbooks/p',null,'bob')).status,403);
  assert.equal((await request('/runs/r',null,'bob')).status,403);
  assert.equal((await request('/runs/r/abort',{},'bob')).status,403);
});
