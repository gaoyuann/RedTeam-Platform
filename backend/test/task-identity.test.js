import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import Database from 'better-sqlite3';
import base from '../src/db/migrations/001_create_tables.js';
import pipelines from '../src/db/migrations/013_add_pipeline_tables.js';
import approval from '../src/db/migrations/015_add_pipeline_approval_status.js';
import identity from '../src/db/migrations/037_task_identity.js';
import { insertNumberedTask, taskNumberDay, creationHash } from '../src/services/taskIdentity.js';
function fixture(path=':memory:',migrate=true){
 const db=new Database(path);db.pragma('foreign_keys=ON');base(db);pipelines(db);approval(db);
 db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','fixture','user')").run();
 if(migrate)identity(db);return db;
}
const input={target:'http://192.0.2.10/',config:{task_name:'Same name'},owner:'owner',now:'2026-10-23T00:00:00.000Z'};
test('Shanghai issuance day interprets UTC and rejects invalid calendar dates',()=>{
 assert.equal(taskNumberDay('2026-10-22 16:00:00'),'20261023');
 assert.equal(taskNumberDay('2026-10-23T00:00:00+08:00'),'20261023');
 for(const value of ['invalid','2026-02-30 00:00:00','2026-10-23T24:00:00Z',null])assert.throws(()=>taskNumberDay(value));
});
test('migration backfills deterministically, preserves links and timestamps, and is repeatable',()=>{
 const db=fixture(':memory:',false);try{
 for(const [id,time] of [['old-a','2026-10-22 16:00:00'],['old-b','2026-10-23T00:00:01+08:00']])
  db.prepare("INSERT INTO pipelines(pipeline_id,target,created_by,created_at) VALUES (?,'192.0.2.10','owner',?)").run(id,time);
 db.prepare("INSERT INTO pipeline_steps(pipeline_id,step_order,step_type) VALUES ('old-a',0,'scan')").run();
 const before=db.prepare('SELECT pipeline_id,created_at,updated_at,status FROM pipelines ORDER BY id').all();identity(db);
 assert.deepEqual(db.prepare('SELECT pipeline_id,created_at,updated_at,status FROM pipelines ORDER BY id').all(),before);
 assert.deepEqual(db.prepare('SELECT task_no FROM pipelines ORDER BY id').all().map(r=>r.task_no),['TASK-20261023-000001','TASK-20261023-000002']);
 assert.equal(db.prepare('SELECT pipeline_id FROM pipeline_steps').get().pipeline_id,'old-a');identity(db);
 assert.equal(insertNumberedTask(db,input).row.task_no,'TASK-20261023-000003');
 assert.throws(()=>db.prepare("UPDATE pipelines SET task_no='TASK-20261023-000099' WHERE pipeline_id='old-a'").run(),/不可修改/);
 }finally{db.close();}
});
test('invalid history rolls back DDL instead of inventing dates',()=>{
 const db=fixture(':memory:',false);try{
 db.prepare("INSERT INTO pipelines(pipeline_id,target,created_at) VALUES ('bad-time','192.0.2.10','invalid')").run();
 assert.throws(()=>identity(db),/迁移已回滚/);
 assert.ok(!db.prepare('PRAGMA table_info(pipelines)').all().some(c=>c.name==='task_no'));
 assert.equal(db.prepare("SELECT count(*) n FROM sqlite_master WHERE name='task_number_counters'").get().n,0);
 }finally{db.close();}
});
test('deletion, rollback, cross day, overflow and request retries preserve unique identity',()=>{
 const db=fixture();try{
 const request={...input,requestId:'request-one',hash:creationHash(input)};
 const a=insertNumberedTask(db,request);assert.equal(a.row.task_no,'TASK-20261023-000001');
 assert.throws(()=>db.prepare('UPDATE pipelines SET task_no=? WHERE pipeline_id=?')
  .run(a.row.task_no.toLowerCase(),a.row.pipeline_id),/不可修改/);
 assert.throws(()=>db.prepare("INSERT INTO pipelines(pipeline_id,task_no,target) VALUES ('duplicate-number',?,'192.0.2.10')")
  .run(a.row.task_no.toLowerCase()),/UNIQUE/);
 assert.match(a.row.pipeline_id,/^pipe_[a-f\d]{8}-[a-f\d]{4}-4[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/);
 assert.equal(insertNumberedTask(db,request).row.pipeline_id,a.row.pipeline_id);
 assert.throws(()=>insertNumberedTask(db,{...request,hash:'changed'}),e=>e.status===409);
 db.prepare('DELETE FROM pipelines WHERE pipeline_id=?').run(a.row.pipeline_id);
 assert.throws(()=>insertNumberedTask(db,request),/已删除/);
 assert.throws(()=>insertNumberedTask(db,{...input,owner:'missing'}),/FOREIGN KEY/);
 assert.equal(insertNumberedTask(db,input).row.task_no,'TASK-20261023-000002');
 assert.equal(insertNumberedTask(db,{...input,now:'2026-10-23T16:00:00Z'}).row.task_no,'TASK-20261024-000001');
 db.prepare("UPDATE task_number_counters SET last_value=999999 WHERE day='20261023'").run();
 assert.equal(insertNumberedTask(db,input).row.task_no,'TASK-20261023-1000000');
 }finally{db.close();}
});
test('concurrent independent connections and restart retain unique high water',async()=>{
 const folder=mkdtempSync(join(tmpdir(),'task-identity-'));const path=join(folder,'identity.db');
 const db=fixture(path);db.pragma('journal_mode=WAL');db.close();try{
 const module=new URL('../src/services/taskIdentity.js',import.meta.url).href;
 const sqlite=new URL('../node_modules/better-sqlite3/lib/index.js',import.meta.url).href;
 const code=`const {parentPort,workerData}=require('node:worker_threads');(async()=>{const {default:DB}=await import(${JSON.stringify(sqlite)});const {insertNumberedTask}=await import(${JSON.stringify(module)});const db=new DB(workerData);db.pragma('busy_timeout=10000');const ids=[];for(let i=0;i<8;i++)ids.push(insertNumberedTask(db,${JSON.stringify(input)}).row.task_no);db.close();parentPort.postMessage(ids)})().catch(e=>{throw e})`;
 const results=await Promise.all(Array.from({length:4},()=>new Promise((resolve,reject)=>{
 const w=new Worker(code,{eval:true,workerData:path});w.once('message',resolve);w.once('error',reject);
 })));
 assert.equal(new Set(results.flat()).size,32);
 const reopened=new Database(path);try{assert.equal(insertNumberedTask(reopened,input).row.task_no,'TASK-20261023-000033');}finally{reopened.close();}
 }finally{rmSync(folder,{recursive:true,force:true});}
});
