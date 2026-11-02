import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { getDb, closeDb } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';

let scanState = 'COMPLETED', analysisCalls = 0;
await mock.module('../src/services/scanAgent.js', { namedExports: { runScanAgent: async (db, pipeline) => {
  db.prepare('INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES(?,?,?,?,?,?)')
    .run('staged-scan',pipeline.target,'web_scan',scanState,pipeline.created_by,pipeline.pipeline_id);
  db.prepare('UPDATE pipelines SET scan_task_id=? WHERE pipeline_id=?').run('staged-scan',pipeline.pipeline_id);
  return {ok:scanState==='COMPLETED',cancelled:scanState==='CANCELLED',scanTaskIds:['staged-scan'],error:scanState==='FAILED'?'fixture scan failed':null};
} } });
await mock.module('../src/services/scanAnalyzer.js', { namedExports: { analyzeScanResults: async () => {
  analysisCalls++;throw Error('automatic analysis must not run in staged mode');
} } });
const { default: routes } = await import('../src/routes/pipelines.js');
const { runPipeline } = await import('../src/services/pipelineEngine.js');

async function fixture(t) {
  analysisCalls=0;
  const db=getDb(':memory:');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('staged-owner','fixture','user',1)").run();
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:'staged-owner',role:'user'};next();});
  app.use('/tasks',routes(db));
  app.use((error,req,res,next)=>res.status(error.status || 500).json({status:'error',error:{message:error.message}}));
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));closeDb();});
  const create=async config=>{
    const res=await fetch(`http://127.0.0.1:${server.address().port}/tasks`,{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({target:'http://fixture.invalid',config})});
    return {status:res.status,body:await res.json()};
  };
  return {db,create};
}

for (const state of ['COMPLETED','FAILED','CANCELLED']) test(`staged ${state} scan ends independently and never generates or executes a global plan`,async t=>{
  const {db,create}=await fixture(t);scanState=state;
  const created=await create({workflow_mode:'staged',task_mode:'assessment',authorization_confirmed:true});
  assert.equal(created.status,201);
  const id=created.body.data.pipeline_id;
  await runPipeline(id);
  const pipeline=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  assert.equal(pipeline.status,state==='COMPLETED'?'completed':state==='CANCELLED'?'cancelled':'failed');
  if(state==='COMPLETED')assert.equal(JSON.parse(pipeline.result).next_action,'select_finding');
  assert.equal(analysisCalls,0);
  assert.equal(db.prepare("SELECT count(*) n FROM pipeline_steps WHERE step_type!='scan'").get().n,0);
  assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
  assert.equal(JSON.parse(pipeline.config).require_approval,true);
});

test('invalid staged modes fail at creation and legacy tasks retain their recorded mode',async t=>{
  const {db,create}=await fixture(t);
  assert.equal((await create({workflow_mode:'automatic'})).status,400);
  assert.equal((await create({workflow_mode:'staged',task_mode:'discovery'})).status,400);
  const legacy=await create({task_mode:'assessment'});
  assert.equal(legacy.status,201);
  assert.equal(legacy.body.data.config.workflow_mode,undefined);
  assert.equal(db.prepare('SELECT count(*) n FROM pipelines').get().n,1);
});
