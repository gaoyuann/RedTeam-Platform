import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {fileURLToPath} from 'node:url';
import {readdir} from 'node:fs/promises';
import {getDb,closeDb} from '../src/db/connection.js';
import {generateSourceVerification,validateSourceDemonstration,recordSourceVerification} from '../src/services/sourceVerification.js';

// Only collection/analysis are replaced. The task API, selection, plan review,
// execution engine and HTTP evidence use the real implementations and loopback.
await mock.module('../src/services/scanExecutor.js',{namedExports:{
  executeScan:async id=>{
    const db=getDb();
    db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(id);
    for(let i=0;i<4;i++) db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity) VALUES (?,'source_finding',?,'medium')")
      .run(id,JSON.stringify({title:'Fixture input '+i,file:'input.c',start_line:i+1,end_line:i+1,
        code:'fixture_input(value);',reason:'Compare controlled test input',preconditions:'Fixture HTTP /check endpoint',cwe:'CWE-20'}));
    return {ok:true,status:'COMPLETED',resultsCount:4};
  },requestScanAbort:()=>{}
}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{
  analyzeScanResults:async()=>({ok:true,data:{tech_stack:[],attack_surface:[],risk_assessment:[],recommended_strategy:[]}})
}});
const {default:pipelineRoutes}=await import('../src/routes/pipelines.js');
const {default:scanRoutes}=await import('../src/routes/scans.js');

async function listen(t,server) {
  server.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  return 'http://127.0.0.1:'+server.address().port;
}
async function fixture(t) {
  const db=getDb(':memory:');t.after(closeDb);
  const directory=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for(const name of (await readdir(directory)).sort()) {
    if(name.includes('import')) continue;
    const migration=await import(directory+name);(migration.default || migration.up)(db);
  }
  for(const [username,role] of [['alice','user'],['admin','admin']]) db.prepare('INSERT OR IGNORE INTO users(username,password,role) VALUES (?,\'fixture\',?)').run(username,role);
  const app=express();app.use(express.json(),(req,res,next)=>{const sub=req.headers['x-user'] || 'alice';req.user={sub,role:sub==='admin'?'admin':'user'};next();});
  app.use('/pipelines',pipelineRoutes(db));app.use('/scans',scanRoutes(db));
  const api=await listen(t,http.createServer(app));
  const request=async(path,body,user='alice',method='POST')=>{
    const response=await fetch(api+path,{method,headers:{'content-type':'application/json','x-user':user},body:JSON.stringify(body)});
    return {status:response.status,data:(await response.json()).data,error:response.ok ? null : response.status};
  };
  return {db,request};
}
async function until(predicate) {
  const deadline=Date.now()+10000;
  while(!predicate() && Date.now()<deadline) await new Promise(resolve=>setTimeout(resolve,10));
  assert.ok(predicate(),'workflow reached expected state');
}
const step=(id,phase,target)=>({name:phase+' #'+id,tool_id:'target-request',phase,finding_ids:[id],
  args_template:[JSON.stringify({url:target+'/check?id='+id+'&value='+(phase==='baseline'?'normal':'boundary')})],
  description:'Fixture input comparison, not a real exploit',expected_evidence:'Compare fixture response; no real vulnerability claim'});

test('task workbench preserves source mode, waits for object selection and executes each selected finding with linked evidence',async t=>{
  const {db,request}=await fixture(t),visits=[];
  const target=await listen(t,http.createServer((req,res)=>{visits.push(req.url);res.end('fixture response: '+req.url);}));
  const keys=['LLM_API_KEY','LLM_BASE_URL','LLM_MODEL'];
  const old=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  t.after(()=>{for(const [key,value] of Object.entries(old)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  let modelCalls=0;
  const model=await listen(t,http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req) raw+=chunk;
    const context=JSON.parse(JSON.parse(raw).messages[1].content);modelCalls++;
    assert.equal(context.findings.length,4);
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({name:'Four object demonstration',steps:context.findings.flatMap(f=>[step(f.id,'baseline',target),step(f.id,'verification',target)])})}}]}));
  }));
  process.env.LLM_API_KEY='fixture-only';process.env.LLM_BASE_URL=model;process.env.LLM_MODEL='fixture';
  const created=await request('/pipelines',{target,config:{scan_mode:'source_assisted',source_url:'/project/code',require_approval:false,
    task_name:'source fixture',authorization_confirmed:true,authorization_scope:target,auto_execute:true}});
  assert.equal(created.status,201);assert.equal(created.data.config.scan_mode,'source_assisted');
  assert.equal(created.data.config.source_url,target+'/project/code/');assert.equal(created.data.config.require_approval,true);
  const id=created.data.pipeline_id;
  assert.equal((await request('/pipelines/'+id+'/start',{})).status,202);
  await until(()=>db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status==='awaiting_approval');
  assert.equal(modelCalls,0);assert.equal(visits.length,0,'no automatic attack before selection');
  const task=db.prepare('SELECT * FROM scan_tasks').get();
  assert.equal(task.scan_type,'source_scan');assert.equal(JSON.parse(task.parameters).source_url,target+'/project/code/');
  assert.equal(JSON.parse(db.prepare('SELECT result FROM pipelines WHERE pipeline_id=?').get(id).result).paused_at,'source_selection');
  assert.equal((await request('/pipelines/'+id+'/approve',{})).status,409,'legacy approve cannot bypass list');
  assert.equal((await request('/pipelines/'+id,{config:{scan_mode:'source_assisted',source_url:'/different/'}},'alice','PUT')).status,409);
  assert.equal((await request('/pipelines',{target,config:{scan_mode:'source_assisted',source_url:'http://example.com/source/'}})).status,400);
  assert.equal((await request('/pipelines',{target:'tcp://127.0.0.1:8091',config:{scan_mode:'source_assisted',source_url:'/code/'}})).status,400);
  const findingIds=db.prepare('SELECT id FROM scan_results ORDER BY id DESC').all().map(row=>row.id);
  assert.equal((await request('/scans/'+task.scan_task_id+'/generate-playbook',{demonstration:true})).status,400);
  const generated=await request('/scans/'+task.scan_task_id+'/generate-playbook',{finding_ids:findingIds,demonstration:true,adaptive:false});
  assert.equal(generated.status,201);assert.equal(generated.data.steps_count,8,'four findings are not truncated to six total steps');
  const metadata=JSON.parse(db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(generated.data.playbook_id).metadata);
  assert.deepEqual(metadata.source_verification.demonstration.objects.map(row=>row.finding_id),findingIds);
  const draft=await request('/pipelines/'+id+'/plan',{playbook_id:generated.data.playbook_id});
  assert.equal(draft.status,200);assert.equal(draft.data.content.steps.length,8);
  const reordered={...draft.data.content,steps:[draft.data.content.steps[1],draft.data.content.steps[0],...draft.data.content.steps.slice(2)]};
  const changed=await request('/pipelines/'+id+'/plan',{revision:draft.data.revision,content:reordered},'alice','PUT');
  assert.equal(changed.status,200);
  const invalidSubmitted=await request('/pipelines/'+id+'/plan/submit',{revision:changed.data.revision});
  assert.equal((await request('/pipelines/'+id+'/plan/approve',{revision:invalidSubmitted.data.revision},'admin')).status,400,
    'editing cannot approve verification before its baseline');
  const reopened=await request('/pipelines/'+id+'/plan/reopen',{revision:invalidSubmitted.data.revision});
  const restored=await request('/pipelines/'+id+'/plan',{revision:reopened.data.revision,content:draft.data.content},'alice','PUT');
  const submitted=await request('/pipelines/'+id+'/plan/submit',{revision:restored.data.revision});
  assert.equal(submitted.status,200);
  assert.equal((await request('/pipelines/'+id+'/plan/approve',{revision:submitted.data.revision},'admin')).status,202);
  await until(()=>db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status==='completed');
  assert.equal(visits.length,8);assert.equal(modelCalls,1,'approved demonstration remains mechanical');
  const run=db.prepare('SELECT * FROM execution_runs').get();assert.equal(run.engine_type,'mechanical');
  const evidence=db.prepare('SELECT * FROM evidence_records ORDER BY step_index').all();assert.equal(evidence.length,8);
  const listed=await request('/scans/'+task.scan_task_id+'/source-verifications',undefined,'alice','GET');
  assert.equal(listed.data.runs[0].run_id,run.run_id,'review lookup includes task-approved cloned playbooks');
  assert.equal(listed.data.runs[0].evidence.length,8);
  for(let i=0;i<findingIds.length;i++) {
    const pair=evidence.slice(i*2,i*2+2).map(row=>JSON.parse(row.evidence_data).source_verification);
    assert.deepEqual(pair.map(row=>row.finding_ids),[[findingIds[i]],[findingIds[i]]]);
    assert.deepEqual(pair.map(row=>row.phase),['baseline','verification']);
    assert.equal(recordSourceVerification(db,findingIds[i],{run_id:run.run_id,status:'inconclusive',
      evidence_ids:evidence.slice(i*2,i*2+2).map(row=>row.id),note:'Fixture only; real deployment requires acceptance testing'},'alice').status,'inconclusive');
  }
});

test('demonstration rejects interleaved, combined, identical and incomplete tests and does not save invented plans',async t=>{
  const {db}=await fixture(t),target='http://127.0.0.1:8999';
  const valid=[step(1,'baseline',target),step(1,'verification',target),step(2,'baseline',target),step(2,'verification',target)];
  validateSourceDemonstration(valid,[1,2],target);
  assert.throws(()=>validateSourceDemonstration([valid[0],valid[2],valid[1],valid[3]],[1,2],target),/逐项/);
  assert.throws(()=>validateSourceDemonstration(valid.map(s=>({...s,finding_ids:[1,2]})),[1,2],target),/逐项/);
  assert.throws(()=>validateSourceDemonstration([valid[0],{...valid[1],args_template:valid[0].args_template}],[1],target),/重复请求/);
  assert.throws(()=>validateSourceDemonstration([valid[0],{...valid[1],optional:true}],[1],target),/必执行/);
  assert.throws(()=>validateSourceDemonstration([valid[1],valid[0]],[1],target),/先正常对照/);
  const tcp='tcp://127.0.0.1:8999';
  const tcpPair=['baseline','verification'].map((phase,i)=>({...step(1,phase,target),args_template:[JSON.stringify({url:tcp,
    exchanges:[{send:'same\n',expect:i?'changed prompt':'prompt'}]})]}));
  assert.throws(()=>validateSourceDemonstration(tcpPair,[1],tcp),/重复请求/);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status) VALUES ('scan','source_scan',?,'COMPLETED')").run(target);
  db.prepare("INSERT INTO scan_results(id,scan_task_id,result_type,result_data) VALUES (1,'scan','source_finding',?)")
    .run(JSON.stringify({title:'memory issue',file:'input.c',start_line:1,code:'copy(input);'}));
  const playbookCount=db.prepare('SELECT COUNT(*) n FROM playbooks').get().n;
  const result=await generateSourceVerification(db,{scan_task_id:'scan',target,status:'COMPLETED'},[1],{demonstration:true,
    llm:async()=>({ok:true,content:JSON.stringify({status:'needs_information',reason:'Local-only memory issue needs a process diagnostic interface'})})});
  assert.equal(result.ok,false);assert.match(result.error,/Local-only/);assert.equal(db.prepare('SELECT COUNT(*) n FROM playbooks').get().n,playbookCount);
});
