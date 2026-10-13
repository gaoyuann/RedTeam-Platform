import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {fileURLToPath} from 'node:url';
import {readdir} from 'node:fs/promises';
import {getDb,closeDb} from '../src/db/connection.js';
import {generateSourceVerification,validateSourceDemonstration,recordSourceVerification} from '../src/services/sourceVerification.js';
import {executeRun} from '../src/services/executionEngine.js';

// Only collection/analysis are replaced. The task API, selection, plan review,
// execution engine and HTTP evidence use the real implementations and loopback.
await mock.module('../src/services/scanExecutor.js',{namedExports:{
  executeScan:async id=>{
    const db=getDb();
    db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(id);
    if(db.prepare('SELECT scan_type FROM scan_tasks WHERE scan_task_id=?').get(id).scan_type==='port_scan') {
      db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity) VALUES (?,'host_discovery',?,'info')")
        .run(id,JSON.stringify({host:'127.0.0.1',status:'up'}));
      return {ok:true,status:'COMPLETED',resultsCount:1};
    }
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

const sourceDraft=ids=>({name:'静态源码测试草稿',description:'需部署程序后复核',required_conditions:['补充真实运行入口与部署版本'],
  objects:ids.map(finding_id=>({finding_id,purpose:'复核源码输入处理',baseline:'正常输入',verification:'确认输入可达后比较边界输入',
    expected_effect:'观察诊断输出，尚未执行',limitations:'仅源码疑点，未确认运行条件'}))});

function sourceOnlyTask(db,count=2) {
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status,parameters,created_by) VALUES ('draft-source','source_scan','/fixture/source','PARTIAL',?, 'alice')")
    .run(JSON.stringify({input_kind:'source'}));
  for(let i=0;i<count;i++) db.prepare("INSERT INTO scan_results(id,scan_task_id,result_type,result_data) VALUES (?,'draft-source','source_finding',?)")
    .run(1622+i,JSON.stringify({title:'Fixture input '+i,file:'input.c',start_line:i+1,code:'fixture_only(input);'}));
  return db.prepare("SELECT * FROM scan_tasks WHERE scan_task_id='draft-source'").get();
}

test('source-only draft covers the exact ten selections, corrects omissions once and preserves order without executing',async t=>{
  const {db}=await fixture(t),task=sourceOnlyTask(db,34),selected=[1655,1644,1642,1640,1638,1636,1634,1632,1630,1622];
  const initialCounts=Object.fromEntries(['playbooks','playbook_steps','task_plans','execution_runs']
    .map(table=>[table,db.prepare('SELECT count(*) n FROM '+table).get().n]));
  let calls=0;
  const llm=async(messages,options)=>{
    calls++;
    const context=JSON.parse(messages[1].content);
    assert.deepEqual(context.selected_finding_ids,selected);
    assert.deepEqual(context.findings.map(row=>row.finding_id),selected);
    assert.equal(context.findings.length,10,'unselected findings do not enter the draft prompt');
    assert.equal(context.findings[0].file,'input.c');assert.equal(context.findings[0].runtime_verified,false);
    assert.equal(context.findings[0].scan_result_id,undefined);
    assert.equal(options.json,true);assert.ok(options.maxTokens>5000);
    if(calls===2) {
      const correction=JSON.parse(messages.at(-1).content);
      assert.equal(correction.correction_required,true);assert.deepEqual(correction.selected_finding_ids,selected);
      assert.match(correction.error,/缺少编号 1622/);assert.equal(messages.at(-2).role,'assistant');
    }
    return {ok:true,content:JSON.stringify(sourceDraft(calls===1 ? selected.slice(0,-1) : [...selected].reverse()))};
  };
  const result=await generateSourceVerification(db,task,selected,{demonstration:true,llm});
  assert.equal(result.ok,true,result.error);assert.equal(calls,2);
  assert.equal(result.executable,false);assert.equal(result.requires_runtime_target,true);
  assert.deepEqual(result.draft.objects.map(row=>row.finding_id),selected);
  assert.equal(result.generation.corrective_attempts,1);assert.equal(result.generation.validation_errors.length,1);
  const saved=db.prepare("SELECT result_data FROM scan_results WHERE result_type='program_plan'").all();
  assert.equal(saved.length,1);assert.equal(JSON.parse(saved[0].result_data).executable,false);
  assert.deepEqual(JSON.parse(saved[0].result_data).generation,result.generation);
  // Old finding rows without new metadata and a repeated generation remain usable.
  const repeated=await generateSourceVerification(db,task,selected,{demonstration:true,llm:async()=>({ok:true,content:JSON.stringify(sourceDraft(selected))})});
  assert.equal(repeated.ok,true,repeated.error);assert.equal(repeated.generation.calls,1);
  assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='program_plan'").get().n,2);
  assert.equal(db.prepare("SELECT result_data FROM scan_results WHERE result_type='program_plan' ORDER BY id").get().result_data,saved[0].result_data);
  for(const [table,count] of Object.entries(initialCounts))
    assert.equal(db.prepare('SELECT count(*) n FROM '+table).get().n,count,'a source-only draft does not create '+table);
});

test('source-only draft rejects wrong or incomplete IDs after one correction and stops immediately on model failure',async t=>{
  const {db}=await fixture(t),task=sourceOnlyTask(db),ids=[1623,1622];
  const invalid=[
    [sourceDraft([1623]),/缺少编号 1622/],
    [sourceDraft([1623,1623,1622]),/重复编号 1623/],
    [sourceDraft([1623,1622,1]),/未选编号 1/],
    [sourceDraft(['1623',1622]),/整数编号/],
    [{...sourceDraft(ids),objects:[{scan_result_id:1623},{scan_result_id:1622}]},/整数编号/],
    [{...sourceDraft(ids),required_conditions:null},/required_conditions/],
    [{...sourceDraft(ids),objects:null},/objects/],
    ['not JSON fixture_only(input);',/有效的JSON/]
  ];
  for(const [draft,error] of invalid) {
    let calls=0;
    const result=await generateSourceVerification(db,task,ids,{demonstration:true,llm:async()=>{
      calls++;return {ok:true,content:typeof draft==='string' ? draft : JSON.stringify(draft)};
    }});
    assert.equal(result.ok,false);assert.equal(calls,2);assert.equal(result.generation.corrective_attempts,1);
    assert.match(result.error,/纠正后仍未/);assert.match(result.error,error);
    assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='program_plan'").get().n,0);
  }
  for(const llm of [async()=>({ok:false,error:'model disconnected'}),async()=>{throw new Error('model disconnected');},
    async()=>({ok:true,content:JSON.stringify({status:'needs_information',reason:'缺少实际输入接口'})})]) {
    const result=await generateSourceVerification(db,task,ids,{demonstration:true,llm});
    assert.equal(result.ok,false);assert.equal(result.generation.calls,1);assert.equal(result.generation.corrective_attempts,0);
  }
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status) VALUES ('other-source','source_scan','/other','COMPLETED')").run();
  const foreign=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('other-source','source_finding','{}')").run().lastInsertRowid);
  let calls=0;const llm=async()=>{calls++;throw new Error('must not call model');};
  for(const selection of [[],[foreign],[1623,1623]]) {
    assert.equal((await generateSourceVerification(db,task,selection,{demonstration:true,llm})).ok,false);
  }
  assert.equal((await generateSourceVerification(db,{...task,status:'RUNNING'},ids,{demonstration:true,llm})).ok,false);
  assert.equal(calls,0);assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='program_plan'").get().n,0);
});

test('source-only generation API retains specific failure reasons in task logs without saving model text',async t=>{
  const {db,request}=await fixture(t),task=sourceOnlyTask(db);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,scan_task_id,created_by) VALUES ('draft-pipeline',?,'awaiting_approval',?,'alice')")
    .run(task.target,task.scan_task_id);
  const keys=['LLM_API_KEY','LLM_BASE_URL','LLM_MODEL'],old=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  t.after(()=>{for(const [key,value] of Object.entries(old)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  let calls=0;
  const model=await listen(t,http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req) raw+=chunk;
    assert.deepEqual(JSON.parse(JSON.parse(raw).messages[1].content).selected_finding_ids,[1623,1622]);calls++;
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({...sourceDraft([1623]),description:'DO_NOT_LOG_MODEL_TEXT'})}}]}));
  }));
  process.env.LLM_API_KEY='fixture-only';process.env.LLM_BASE_URL=model;process.env.LLM_MODEL='fixture';
  const result=await request('/scans/'+task.scan_task_id+'/generate-playbook',{finding_ids:[1623,1622],demonstration:true});
  assert.equal(result.status,400);assert.equal(calls,2);
  const logs=db.prepare("SELECT level,message FROM pipeline_logs WHERE pipeline_id='draft-pipeline' ORDER BY id").all();
  assert.match(logs[0].message,/漏洞编号 1623,1622/);assert.equal(logs.at(-1).level,'warn');
  assert.match(logs.at(-1).message,/纠正后仍未通过校验.*缺少编号 1622/);
  assert.match(logs.at(-1).message,/模型调用 2 次，纠正 1 次/);
  assert.ok(logs.every(row=>!row.message.includes('DO_NOT_LOG_MODEL_TEXT') && !row.message.includes('fixture_only')));
  assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='program_plan'").get().n,0);
  assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
  assert.equal(db.prepare("SELECT status FROM pipelines WHERE pipeline_id='draft-pipeline'").get().status,'awaiting_approval');
});

test('source plan corrects malformed model URLs once and still rejects unresolved scope or missing conditions',async t=>{
  const {db}=await fixture(t),target='http://127.0.0.1:8999';
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status) VALUES ('url-repair','source_scan',?,'COMPLETED')").run(target);
  db.prepare("INSERT INTO scan_results(id,scan_task_id,result_type,result_data) VALUES (1,'url-repair','source_finding',?)")
    .run(JSON.stringify({title:'fixture input',file:'input.c',start_line:1,code:'copy(input);'}));
  const task={scan_task_id:'url-repair',target,status:'COMPLETED'};
  const plan=url=>({name:'Input comparison',steps:[step(1,'baseline',url),step(1,'verification',url)]});
  let calls=0;
  const repaired=await generateSourceVerification(db,task,[1],{demonstration:true,llm:async messages=>{
    calls++;
    if(calls===2) {
      const correction=JSON.parse(messages.at(-1).content);
      assert.equal(correction.correction_required,true);assert.equal(correction.target,new URL(target).href);assert.match(correction.error,/Invalid URL/);
      assert.equal(messages.at(-2).role,'assistant');
    }
    return {ok:true,content:JSON.stringify(plan(calls===1?'<target>':target))};
  }});
  assert.equal(repaired.ok,true,repaired.error);assert.equal(calls,2);
  const metadata=JSON.parse(db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(repaired.playbook_id).metadata);
  assert.equal(metadata.source_verification.generation.corrective_attempts,1);
  assert.deepEqual(metadata.source_verification.generation.validation_errors,['Invalid URL']);
  const count=db.prepare('SELECT count(*) n FROM playbooks').get().n;
  calls=0;
  const refused=await generateSourceVerification(db,task,[1],{demonstration:true,llm:async()=>{
    calls++;return {ok:true,content:JSON.stringify(plan('http://example.com:8999'))};
  }});
  assert.equal(refused.ok,false);assert.equal(calls,2);assert.match(refused.error,/纠正后仍未/);
  assert.equal(db.prepare('SELECT count(*) n FROM playbooks').get().n,count,'no out-of-scope plan is saved');
  calls=0;
  const insufficient=await generateSourceVerification(db,task,[1],{demonstration:true,llm:async()=>{
    calls++;return {ok:true,content:JSON.stringify({status:'needs_information',reason:'Need diagnostic support'})};
  }});
  assert.equal(insufficient.ok,false);assert.equal(calls,1);assert.equal(insufficient.error,'Need diagnostic support');
  calls=0;
  const disconnected=await generateSourceVerification(db,task,[1],{demonstration:true,llm:async()=>{calls++;return {ok:false,error:'model disconnected'};}});
  assert.equal(disconnected.ok,false);assert.equal(calls,1);assert.equal(db.prepare('SELECT count(*) n FROM playbooks').get().n,count);
});

test('response comparison selects the same-address baseline and retains separate diagnostic source versions',async t=>{
  const {db}=await fixture(t);
  const target=await listen(t,http.createServer(async(req,res)=>{let body='';for await(const part of req) body+=part;res.end('fixture:'+body);}));
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status) VALUES ('comparison','source_scan',?,'COMPLETED')").run(target);
  const finding=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('comparison','source_finding',?)")
    .run(JSON.stringify({file:'input.c',start_line:2,title:'Fixture comparison',reason:'Controlled input',code:'copy(input);',source_sha256:'frozen',snapshot_id:'v1'})).lastInsertRowid);
  db.prepare("INSERT INTO source_audits(scan_task_id,snapshot_id,connection_id,manifest,analysis,created_at) VALUES ('comparison','v1','fixture',?,'{}',datetime('now'))")
    .run(JSON.stringify({files:[{path:'input.c',sha256:'frozen',end_line:8}]}));
  const steps=[['baseline','/check','normal','POST'],['baseline','/other','other','POST'],['baseline','/check','','GET'],['verification','/check','boundary','POST']].map(([phase,path,body,method],index)=>({
    name:phase+index,tool_id:'target-request',phase,finding_ids:[finding],description:'Controlled comparison',expected_evidence:'Fixture response difference only',
    args_template:[JSON.stringify({url:target+path,method,body})],
    ...(phase==='verification'?{criteria:{kind:'response_differs',limitations:'Fixture text differences do not prove a vulnerability'}}:{})}));
  const generated=await generateSourceVerification(db,{scan_task_id:'comparison',target,status:'COMPLETED'},[finding],{
    demonstration:true,llm:async()=>({ok:true,content:JSON.stringify({name:'Address comparison',steps})})});
  assert.equal(generated.ok,true,generated.error);
  db.prepare("INSERT INTO execution_runs(run_id,playbook_id,target,scan_task_id,status,engine_type) VALUES ('comparison-run',?,?,'comparison','PENDING','mechanical')").run(generated.playbook_id,target);
  assert.equal((await executeRun('comparison-run')).ok,true);
  const evidence=db.prepare("SELECT id,evidence_data FROM evidence_records WHERE run_id='comparison-run' ORDER BY step_index").all();
  assert.equal(evidence.length,4);
  const result=JSON.parse(evidence[3].evidence_data);
  assert.equal(result.source_comparison.status,'matched');assert.equal(result.source_comparison.baseline_evidence_id,evidence[0].id);
  assert.equal(result.source_verification.source_versions[0].end_line,8);assert.equal(result.source_comparison.runtime_verified,false);
});

test('legacy source task with a separately declared HTTP root collects real response and executes reviewed verification',async t=>{
  const {db}=await fixture(t),visits=[];
  const target=await listen(t,http.createServer((req,res)=>{visits.push(req.url);res.end(req.url==='/' ? '<a href="/check">Fixture CGI handler</a>' : 'fixture response '+req.url);}));
  const task=sourceOnlyTask(db,1);
  task.target=target+'/';task.parameters=JSON.stringify({input_kind:'source',source_url:target+'/source/'});
  db.prepare('UPDATE scan_tasks SET target=?,parameters=? WHERE scan_task_id=?').run(task.target,task.parameters,task.scan_task_id);
  const llm=async messages=>{
    const context=JSON.parse(messages[1].content);
    assert.equal(context.target,target+'/');
    assert.ok(context.evidence.some(row=>row.type==='application_observation' && row.data.connected===true));
    return {ok:true,content:JSON.stringify({name:'Fixture CGI verification',steps:[step(1622,'baseline',target),step(1622,'verification',target)]})};
  };
  const result=await generateSourceVerification(db,task,[1622],{demonstration:true,llm});
  assert.equal(result.ok,true,result.error);assert.deepEqual(visits,['/']);
  assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='program_plan'").get().n,0);
  const metadata=JSON.parse(db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(result.playbook_id).metadata);
  assert.equal(metadata.source_verification.reproducibility.deployment_version_verified,false);
  // Repeated generation uses existing matching evidence, never performs attack requests.
  assert.equal((await generateSourceVerification(db,task,[1622],{demonstration:true,llm})).ok,true);
  assert.deepEqual(visits,['/']);
  db.prepare("INSERT INTO execution_runs(run_id,playbook_id,target,scan_task_id,status,engine_type) VALUES ('legacy-cgi',?,?,?,'PENDING','mechanical')")
    .run(result.playbook_id,result.target,task.scan_task_id);
  assert.equal((await executeRun('legacy-cgi')).ok,true);
  assert.deepEqual(visits,['/','/check?id=1622&value=normal','/check?id=1622&value=boundary']);
  assert.equal(db.prepare("SELECT count(*) n FROM evidence_records WHERE run_id='legacy-cgi'").get().n,2);
});

test('legacy runtime recovery stops on unreachable or mismatched response and can retry without saving a false plan',async t=>{
  const {db}=await fixture(t),task=sourceOnlyTask(db,1);
  const existingPlans=db.prepare('SELECT count(*) n FROM playbooks').get().n;
  task.target='http://192.0.2.30:8089/';task.parameters=JSON.stringify({input_kind:'source',source_url:task.target+'source/'});
  let modelCalls=0;
  const llm=async()=>{modelCalls++;return {ok:true,content:JSON.stringify({status:'needs_information',reason:'缺少实际 CGI 路由'})};};
  for(const response of [{success:false,error:'ECONNREFUSED'},
    {success:true,stdout:JSON.stringify({connected:true,url:'http://192.0.2.99:8089/'})}]) {
    const result=await generateSourceVerification(db,task,[1622],{llm,request:async()=>response});
    assert.equal(result.ok,false);assert.match(result.error,/响应采集失败|不属于当前测试地址/);
  }
  assert.equal(modelCalls,0);
  const retried=await generateSourceVerification(db,task,[1622],{llm,request:async(args,options)=>{
    assert.equal(options.target,task.target);assert.equal(JSON.parse(args[0]).method,'GET');
    return {success:true,stdout:JSON.stringify({connected:true,url:task.target,status_code:200,response:'index'})};
  }});
  assert.equal(retried.ok,false);assert.match(retried.error,/缺少实际 CGI 路由/);assert.equal(modelCalls,1);
  assert.equal(db.prepare('SELECT count(*) n FROM playbooks').get().n,existingPlans);
  assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='program_plan'").get().n,0);
});

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
  const network=db.prepare("SELECT * FROM scan_tasks WHERE scan_type='port_scan'").get();
  assert.equal(network.target,task.target);assert.equal(JSON.parse(network.parameters).pipeline_id,id);
  assert.equal(JSON.parse(network.parameters).discover_topology,true);
  assert.equal(task.scan_type,'source_scan');assert.equal(JSON.parse(task.parameters).source_url,target+'/project/code/');
  assert.equal(JSON.parse(db.prepare('SELECT result FROM pipelines WHERE pipeline_id=?').get(id).result).paused_at,'source_selection');
  assert.deepEqual((await request('/pipelines/'+id+'/plan/sources',undefined,'alice','GET')).data,[],
    'source tasks do not offer unrelated templates before generation');
  assert.equal((await request('/pipelines/'+id+'/approve',{})).status,409,'legacy approve cannot bypass list');
  assert.equal((await request('/pipelines/'+id,{config:{scan_mode:'source_assisted',source_url:'/different/'}},'alice','PUT')).status,409);
  assert.equal((await request('/pipelines',{target,config:{scan_mode:'source_assisted',source_url:'http://example.com/source/'}})).status,400);
  assert.equal((await request('/pipelines',{target:'tcp://127.0.0.1:8091',config:{scan_mode:'source_assisted',source_url:'/code/'}})).status,400);
  const findingIds=db.prepare("SELECT id FROM scan_results WHERE scan_task_id=? AND result_type='source_finding' ORDER BY id DESC").all(task.scan_task_id).map(row=>row.id);
  assert.equal((await request('/scans/'+task.scan_task_id+'/generate-playbook',{demonstration:true})).status,400);
  const generated=await request('/scans/'+task.scan_task_id+'/generate-playbook',{finding_ids:findingIds,demonstration:true,adaptive:false});
  assert.equal(generated.status,201);assert.equal(generated.data.steps_count,8,'four findings are not truncated to six total steps');
  db.prepare("INSERT INTO playbooks(playbook_id,name) VALUES ('generic','Unrelated template')").run();
  db.prepare("INSERT INTO playbook_steps(playbook_id,step_index,step_id,name,tool_id) VALUES ('generic',0,'generic-step','Unrelated step','nmap')").run();
  const sources=await request('/pipelines/'+id+'/plan/sources',undefined,'alice','GET');
  assert.deepEqual(sources.data.map(row=>row.playbook_id),[generated.data.playbook_id],
    'saved source plan is recoverable through the task-scoped source list');
  assert.equal(sources.data[0].steps_count,8);
  assert.equal((await request('/pipelines/'+id+'/plan',{playbook_id:'generic'})).status,400);
  assert.equal((await request('/pipelines/'+id+'/plan/sources',undefined,'bob','GET')).status,403);
  const metadata=JSON.parse(db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(generated.data.playbook_id).metadata);
  assert.deepEqual(metadata.source_verification.demonstration.objects.map(row=>row.finding_id),findingIds);
  const draft=await request('/pipelines/'+id+'/plan',{playbook_id:generated.data.playbook_id});
  assert.equal(draft.status,200);assert.equal(draft.data.content.steps.length,8);
  assert.equal(db.prepare("SELECT status FROM pipeline_steps WHERE pipeline_id=? AND step_type='generate'").get(id).status,'completed');
  assert.equal(db.prepare('SELECT generated_playbook_id FROM pipelines WHERE pipeline_id=?').get(id).generated_playbook_id,null,
    'draft generation does not bypass approval');
  assert.equal((await request('/pipelines/'+id+'/plan',{playbook_id:generated.data.playbook_id})).status,409,
    'repeated clicks cannot replace an existing draft');
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
  assert.throws(()=>validateSourceDemonstration([valid[0],{...valid[1],criteria:{kind:'response_differs'}}],[1],target),/同一URL/);
  const bodyPair=['baseline','verification'].map((phase,index)=>({...step(1,phase,target),
    args_template:[JSON.stringify({url:target+'/check',method:'POST',body:index?'boundary':'normal'})],
    ...(index?{criteria:{kind:'response_differs'}}:{})}));
  validateSourceDemonstration(bodyPair,[1],target);
  assert.throws(()=>validateSourceDemonstration([bodyPair[0],{...bodyPair[1],args_template:[JSON.stringify({url:target+'/check',method:'GET'})]}],[1],target),/同一URL和请求方法/);
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

test('generation groups independent findings and corrects exact missing-step errors',async t=>{
  const {db}=await fixture(t),task=sourceOnlyTask(db,2),target='http://127.0.0.1:8999';
  task.target=target;task.parameters=JSON.stringify({input_kind:'runtime'});
  const a=1622,b=1623;
  const original=[step(b,'baseline',target),step(a,'baseline',target),step(b,'verification',target),step(a,'verification',target)];
  const result=await generateSourceVerification(db,task,[a,b],{demonstration:true,
    llm:async()=>({ok:true,content:JSON.stringify({name:'Grouped fixture',steps:original})})});
  assert.equal(result.ok,true,result.error);
  const saved=db.prepare('SELECT args_template FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(result.playbook_id);
  assert.deepEqual(saved.map(row=>JSON.parse(row.args_template)),[original[1],original[3],original[0],original[2]].map(item=>item.args_template));
  let calls=0;
  const repaired=await generateSourceVerification(db,task,[a],{demonstration:true,llm:async messages=>{
    calls++;
    if(calls===2) {
      const correction=JSON.parse(messages.at(-1).content);
      assert.match(correction.error,/#1622.*实际独立步骤为1步/);
      assert.deepEqual(correction.selected_finding_ids,[a]);
      assert.deepEqual(correction.step_groups[0].phases,['baseline','verification']);
    }
    return {ok:true,content:JSON.stringify({name:'Correction',steps:calls===1?[step(a,'baseline',target)]:[step(a,'baseline',target),step(a,'verification',target)]})};
  }});
  assert.equal(repaired.ok,true,repaired.error);assert.equal(calls,2);
  const count=db.prepare('SELECT count(*) n FROM playbooks').get().n;
  for(const steps of [[step(a,'verification',target),step(a,'baseline',target),step(b,'baseline',target),step(b,'verification',target)],
    [step(a,'baseline',target),{...step(a,'verification',target),finding_ids:[a,b]}]]) {
    const failed=await generateSourceVerification(db,task,[a,b],{demonstration:true,
      llm:async()=>({ok:true,content:JSON.stringify({name:'Invalid fixture',steps})})});
    assert.equal(failed.ok,false);
  }
  assert.equal(db.prepare('SELECT count(*) n FROM playbooks').get().n,count);
});
