import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import base from '../src/db/migrations/001_create_tables.js';
import pipelines from '../src/db/migrations/013_add_pipeline_tables.js';
import integrity from '../src/db/migrations/029_scan_result_integrity.js';
import plans from '../src/db/migrations/022_task_plans.js';
import identity from '../src/db/migrations/037_task_identity.js';
import deletion from '../src/db/migrations/041_task_deletions.js';
import routes from '../src/routes/pipelines.js';
import scans from '../src/routes/scans.js';
import topologyRoutes from '../src/routes/topology.js';
import errorHandler from '../src/middleware/errorHandler.js';
import { deleteTask, isScanTaskDeleted } from '../src/services/taskDeletion.js';
import { existingCreation } from '../src/services/taskIdentity.js';

function fixture(migrated=true) {
  const db=new Database(':memory:');db.pragma('foreign_keys=ON');
  base(db);pipelines(db);plans(db);integrity(db);identity(db);if(migrated){deletion(db);deletion(db);}
  for(const user of ['alice','bob'])db.prepare("INSERT INTO users(username,password,role) VALUES (?,'fixture','user')").run(user);
  db.prepare("INSERT INTO users(username,password,role) VALUES ('admin','fixture','admin')").run();
  const add=(id,status='completed')=>{
    db.prepare("INSERT INTO pipelines(pipeline_id,task_no,target,status,created_by) VALUES (?,?,'192.0.2.1',?,'alice')")
      .run(id,'TASK-20261031-'+String(db.prepare('SELECT count(*) n FROM pipelines').get().n+1).padStart(6,'0'),status);
    return db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  };
  return {db,add};
}
async function api(t,db) {
  const app=express();app.use(express.json());app.use((req,res,next)=>{const sub=req.headers['x-actor']||'alice';req.user={sub,role:sub==='admin'?'admin':'user'};next();});
  app.use('/api/pipelines',routes(db));app.use('/api/scans',scans(db));app.use('/api/topology',topologyRoutes(db));app.use(errorHandler);
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));db.close();});
  return async(path,method='GET',actor='alice')=>fetch(`http://127.0.0.1:${server.address().port}${path}`,{method,headers:{'x-actor':actor,'Content-Type':'application/json'},...(method==='POST'?{body:'{}'}:{})});
}
test('linked completed task deletes idempotently without breaking evidence, retry provenance or identity',async t=>{
  const {db,add}=fixture();const p=add('pipe_original');add('pipe_retry');
  db.prepare('UPDATE pipelines SET config=? WHERE pipeline_id=?').run(JSON.stringify({retry_of_pipeline_id:p.pipeline_id}),'pipe_retry');
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,pipeline_id,created_by) VALUES ('scan','192.0.2.1','port_scan','COMPLETED',?,'alice')").run(p.pipeline_id);
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('scan','open_port','{}')").run();
  db.prepare("INSERT INTO task_creation_requests(owner,request_id,request_hash,pipeline_id,task_no) VALUES ('alice','request-fixture','hash',?,?)").run(p.pipeline_id,p.task_no);
  const request=await api(t,db);
  assert.equal((await request('/api/pipelines/'+p.pipeline_id,'DELETE','bob')).status,403);
  assert.equal((await request('/api/pipelines/'+p.pipeline_id,'DELETE')).status,200);
  assert.equal((await request('/api/pipelines/'+p.pipeline_id,'DELETE')).status,200);
  assert.equal(db.prepare('SELECT count(*) n FROM task_deletions').get().n,1);
  assert.equal(db.prepare('SELECT count(*) n FROM scan_results').get().n,1);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  const list=await (await request('/api/pipelines?view=list')).json();assert.deepEqual(list.data.map(p=>p.pipeline_id),['pipe_retry']);assert.equal(list.meta.visible_total,1);
  assert.equal((await (await request('/api/pipelines?view=list&search='+p.task_no)).json()).data.length,0);
  assert.equal((await request('/api/pipelines/lookup?task_no='+p.task_no)).status,404);
  assert.equal((await (await request('/api/pipelines/analysis-index')).json()).data.records.length,1);
  assert.equal((await request('/api/pipelines/'+p.pipeline_id)).status,200,'historical source remains readable');
  assert.equal((await request('/api/pipelines/'+p.pipeline_id+'/start','POST')).status,409);
  assert.equal((await request('/api/scans/scan/retry','POST')).status,409);
  assert.equal((await request('/api/topology/from-pipeline/'+p.pipeline_id+'/node-scans','POST')).status,409);
  assert.throws(()=>existingCreation(db,'alice','request-fixture','hash'),/已删除/);
  db.prepare('UPDATE pipelines SET scan_task_id=? WHERE pipeline_id=?').run(' scan ',p.pipeline_id);
  db.prepare('UPDATE scan_tasks SET pipeline_id=NULL WHERE scan_task_id=?').run('scan');
  assert.equal(isScanTaskDeleted(db,db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get('scan')),true,'legacy scan links remain protected');
});
test('active tasks, scans, unconfirmed tools and verification stops cannot be hidden',()=>{
  const {db,add}=fixture();try{
    for(const status of ['running']) {const p=add('pipe_'+status,status);assert.throws(()=>deleteTask(db,p,{sub:'alice'}),{status:409});}
    const p=add('pipe_scan');
    db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,pipeline_id) VALUES ('s','192.0.2.1','port_scan','RUNNING',?)").run(p.pipeline_id);
    assert.throws(()=>deleteTask(db,p,{sub:'alice'}),/关联扫描/);
    db.prepare("UPDATE scan_tasks SET status='COMPLETED'").run();
    db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,state,started_at,outcome) VALUES ('tool','s','nmap','completed','now',?)").run(JSON.stringify({stopped:false}));
    assert.throws(()=>deleteTask(db,p,{sub:'alice'}),/工具停止/);
    for(const [state,outcome] of [['completed','{}'],['completed',null],['completed','not-json'],
      ['unknown',JSON.stringify({stopped:true})]]) {
      db.prepare('UPDATE scan_tool_runs SET state=?,outcome=?').run(state,outcome);
      assert.throws(()=>deleteTask(db,p,{sub:'alice'}),error=>error.status===409 && /工具停止/.test(error.message));
      assert.equal(db.prepare('SELECT count(*) n FROM task_deletions').get().n,0);
    }
    db.prepare("UPDATE scan_tool_runs SET state='completed'").run();
    db.prepare("UPDATE scan_tool_runs SET outcome=?").run(JSON.stringify({stopped:true}));
    db.exec("CREATE TABLE finding_verification_attempts(pipeline_id TEXT,state TEXT,stop_confirmed INTEGER)");
    db.prepare("INSERT INTO finding_verification_attempts VALUES (?,'unknown',0)").run(p.pipeline_id);
    assert.throws(()=>deleteTask(db,p,{sub:'alice'}),/漏洞验证/);
    assert.equal(db.prepare('SELECT count(*) n FROM task_deletions').get().n,0);
    db.prepare("UPDATE finding_verification_attempts SET state='completed',stop_confirmed=1").run();
    deleteTask(db,p,{sub:'alice'});assert.equal(db.prepare('SELECT count(*) n FROM task_deletions').get().n,1);
    deleteTask(db,add('pipe_created','created'),{sub:'alice'});
    deleteTask(db,add('pipe_paused','paused'),{sub:'alice'});
    const pending=add('pipe_pending_run');
    db.prepare("INSERT INTO execution_runs(run_id,target,user_sub,status) VALUES ('pending-run','192.0.2.1','alice','PENDING')").run();
    db.prepare("UPDATE pipelines SET run_id='pending-run' WHERE pipeline_id=?").run(pending.pipeline_id);
    assert.throws(()=>deleteTask(db,pending,{sub:'alice'}),/关联执行/);
    db.exec("CREATE TRIGGER reject_deletion BEFORE INSERT ON task_deletions BEGIN SELECT RAISE(ABORT,'fixture failure'); END");
    assert.throws(()=>deleteTask(db,add('pipe_rollback'),{sub:'alice'}),/fixture failure/);
    assert.equal(db.prepare("SELECT count(*) n FROM task_deletions WHERE pipeline_id='pipe_rollback'").get().n,0);
  }finally{db.close();}
});
test('legacy database supports lists and returns actionable migration error on deletion',async t=>{
 const {db,add}=fixture(false);add('pipe_legacy');const request=await api(t,db);
 assert.equal((await request('/api/pipelines?view=list')).status,200);
 const response=await request('/api/pipelines/pipe_legacy','DELETE');assert.equal(response.status,503);assert.match((await response.json()).error.message,/迁移/);
 assert.equal(db.prepare('SELECT count(*) n FROM pipelines').get().n,1);
});
