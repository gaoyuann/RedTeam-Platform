import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import BetterSqlite3 from 'better-sqlite3';
import {fileURLToPath} from 'node:url';
import {runMigrations} from '../src/db/migrate.js';
import playbookRoutes from '../src/routes/playbooks.js';
import {createTaskPlan,transitionTaskPlan,getTaskPlanSources} from '../src/services/taskPlan.js';

for(const playbookId of ['golden_dvwa_max_tools','recon_dir_enum']) {
test(`${playbookId}: catalogue retains one reusable template while task execution versions stay frozen and owner scoped`,async t=>{
  const db=new BetterSqlite3(':memory:');t.after(()=>db.close());db.pragma('foreign_keys=ON');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  for(const [username,role] of [['alice','user'],['bob','user']]) db.prepare("INSERT INTO users(username,password,role) VALUES (?,'fixture',?)").run(username,role);
  const actor={sub:'alice',role:'user'},admin={sub:'admin',role:'admin'};
  const source=db.prepare('SELECT * FROM playbooks WHERE playbook_id=?').get(playbookId);assert.ok(source);
  const originalSteps=db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(source.playbook_id);
  const taskName=playbookId==='golden_dvwa_max_tools'?'DVWA 本次测试':'目录枚举本次测试';
  const config={task_name:taskName,authorization_confirmed:true,authorization_scope:'fixture only',auto_execute:true};
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config) VALUES ('catalog-task','http://fixture.invalid/','awaiting_approval','alice',?)").run(JSON.stringify(config));
  const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='catalog-task'").get();
  const draft=createTaskPlan(db,pipeline,actor,source.playbook_id);
  const submitted=transitionTaskPlan(db,pipeline,actor,'submit',{revision:draft.revision});
  const approved=transitionTaskPlan(db,pipeline,admin,'approve',{revision:submitted.revision});
  const snapshot=db.prepare('SELECT * FROM playbooks WHERE playbook_id=?').get(approved.approved_playbook_id);
  assert.equal(snapshot.name,source.name,'approved name stays identical to the reviewed content for trace integrity');
  assert.equal(JSON.parse(snapshot.metadata).task_plan.display_name,`${source.name} · ${taskName} · 执行版本 v2`);
  assert.equal(JSON.parse(snapshot.metadata).task_plan.source_playbook_id,source.playbook_id);
  assert.equal(db.prepare('SELECT name FROM playbooks WHERE playbook_id=?').get(source.playbook_id).name,source.name);
  assert.deepEqual(db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(source.playbook_id),originalSteps);
  assert.ok(!getTaskPlanSources(db,pipeline,actor).some(row=>row.playbook_id===snapshot.playbook_id));
  assert.throws(()=>transitionTaskPlan(db,pipeline,admin,'approve',{revision:submitted.revision}),error=>error.status===409);

  const app=express();app.use(express.json(),(req,res,next)=>{const sub=req.headers['x-user'] || 'alice';req.user={sub,role:sub==='admin'?'admin':'user'};next();});
  app.use('/playbooks',playbookRoutes(db));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  async function request(path,user='alice',method='GET',body) {
    const response=await fetch('http://127.0.0.1:'+server.address().port+'/playbooks'+path,{method,headers:{'x-user':user,'content-type':'application/json'},body:JSON.stringify(body)});
    return {...await response.json(),status:response.status};
  }
  for(const user of ['alice','admin']) {
    const catalog=await request('?includeGenerated=true',user);assert.equal(catalog.status,200);
    assert.equal(catalog.data.filter(row=>row.name===source.name).length,1);
    assert.ok(!catalog.data.some(row=>row.playbook_id===snapshot.playbook_id));
    const history=await request('?includeGenerated=true&includeSnapshots=true',user);
    assert.ok(history.data.some(row=>row.playbook_id===snapshot.playbook_id));
  }
  assert.ok(!(await request('?includeGenerated=true&includeSnapshots=true','bob')).data.some(row=>row.playbook_id===snapshot.playbook_id));
  const detail=await request('/'+snapshot.playbook_id);assert.equal(detail.data.access.snapshot,true);
  assert.equal(detail.data.display_name,`${source.name} · ${taskName} · 执行版本 v2`);
  assert.equal((await request('/'+snapshot.playbook_id,'bob')).status,403);
  assert.equal((await request('/'+snapshot.playbook_id,'admin','PUT',{name:'tampered'})).status,409);
  assert.equal((await request('/'+snapshot.playbook_id,'admin','DELETE')).status,409);
  // Old snapshots still disappear from the catalogue, including records whose
  // metadata was lost: the approved task association remains authoritative.
  db.prepare('UPDATE playbooks SET name=?,metadata=?,is_generated=0 WHERE playbook_id=?').run(source.name,'{}',snapshot.playbook_id);
  const legacy=await request('?includeGenerated=true','admin');assert.equal(legacy.data.filter(row=>row.name===source.name).length,1);
  assert.equal((await request('/'+snapshot.playbook_id)).data.access.snapshot,true);
  // Editing a reusable template cannot change the steps already approved.
  db.prepare("UPDATE playbook_steps SET name='changed template' WHERE playbook_id=?").run(source.playbook_id);
  assert.deepEqual(db.prepare('SELECT name FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(snapshot.playbook_id).map(row=>row.name),originalSteps.map(row=>row.name));
});
}
