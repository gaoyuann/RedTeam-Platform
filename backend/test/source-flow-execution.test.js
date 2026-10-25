import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';
import scanRoutes from '../src/routes/scans.js';
import verificationRoutes from '../src/routes/findingVerifications.js';
import {createCscanClient,cscanConfig} from '../src/services/cscanClient.js';
import {createSourceFlowTask,dispatchSourceFlow} from '../src/services/sourceFlowWorkflow.js';
import {launchVerification} from '../src/services/findingVerificationRunner.js';

async function listen(t,handler) {
  const server=http.createServer(handler);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
  return 'http://127.0.0.1:'+server.address().port;
}
async function until(predicate) {
  for(let i=0;i<800;i++){const result=predicate();if(result)return result;await delay(10);}
  assert.fail('workflow did not settle');
}

test('target Flow -> retained report -> original Assistant artifacts -> plan -> real loopback execution -> linked evidence',async t=>{
  const db=getDb(':memory:');t.after(closeDb);
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('flow_alice','fixture','user',1)").run();
  const actor={sub:'flow_alice',role:'user'};
  const root=await mkdtemp(join(tmpdir(),'source-chain-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const calls=[],requests=[],assistants=[],logs=new Map();
  let slow=false,creates=0,generations=0;
  const target=await listen(t,(req,res)=>{
    requests.push(req.url);
    if(slow){req.on('close',()=>{});return;}
    res.setHeader('content-type','text/plain');
    res.end(req.url.includes('verification')?'fixture-alternate':'fixture-baseline');
  });
  const runtime=target+'/check';
  const report=['Source-Access: available','## Fixture input comparison','File: main.c','Line: 2',
    'Severity: low','CWE: CWE-20','Evidence: Compare fixture responses only',
    'Preconditions: Loopback simulation; no real defect asserted','Remediation: Review inputs',
    'Existing verification draft: GET /check?mode=verification'].join('\n');
  const cscan=await listen(t,async(req,res)=>{
    let raw='';for await(const part of req)raw+=part;
    const {query,variables:v}=JSON.parse(raw);calls.push(query);
    let data;
    const task={id:'1',flowId:'1',status:'finished',result:report,subtasks:[{id:'11',status:'finished',result:''}]};
    if(query.includes('createFlow')) {
      creates++;assert.ok(v.input.includes(target+'/source/'));
      await mkdir(join(root,'flow-1/src'),{recursive:true});
      await writeFile(join(root,'flow-1/src/main.c'),'int main(void) {\n return 0;\n}\n');
      data={createFlow:{id:'1',status:'running'}};
    } else if(query.includes('createAssistant')) {
      const id=String(assistants.length+1);
      assistants.push({id,flowId:'1',useAgents:false,status:'waiting'});
      const reply={summary:'Existing simulated observation only',scripts:[{name:'Fixture request',language:'http',
          content:'GET /check?mode=verification',source_type:'task',source_id:'1',usage:'Only loopback fixture'}]};
      logs.set(id,[{id:'1',flowId:'1',assistantId:id,type:'input',message:v.input},
        {id:'2',flowId:'1',assistantId:id,type:'answer',message:JSON.stringify(reply),appendPart:false}]);
      data={createAssistant:{assistant:assistants.at(-1)}};
    } else if(query.includes('assistantLogs'))data={assistantLogs:logs.get(v.assistantId) || []};
    else if(query.includes('assistants('))data={assistants};
    else if(query.includes('CScanPayloadEvidence'))data={tasks:[task],terminalLogs:[],messageLogs:[]};
    else if(query.includes('finishFlow'))data={finishFlow:'success'};
    else if(query.includes('stopFlow'))data={stopFlow:'success'};
    else if(query.includes('CScanReport'))data={tasks:[task]};
    else data={flow:{id:'1',status:'waiting'},tasks:[task]};
    res.setHeader('content-type','application/json');res.end(JSON.stringify({data}));
  });
  const env={CSCAN_API_URL:cscan,CSCAN_API_TOKEN:'fixture-only',CSCAN_PROVIDER:'fixture',
    CSCAN_WORK_DIR:root,CSCAN_POLL_MS:'10',CSCAN_TIMEOUT_MS:'3000',CSCAN_REQUEST_TIMEOUT_MS:'1000'};
  const previous=Object.fromEntries(Object.keys(env).map(k=>[k,process.env[k]]));Object.assign(process.env,env);
  t.after(()=>{for(const [k,v] of Object.entries(previous))if(v===undefined)delete process.env[k];else process.env[k]=v;});
  const client=await createCscanClient(cscanConfig());
  const dependencies={cscanClient:client,pollMs:1,collectionTimeoutMs:2000,llm:async messages=>{
    generations++;
    const context=JSON.parse(messages[1].content);
    assert.equal(context.collected_payloads.scripts[0].source_id,'1');
    assert.equal(context.target,runtime);
    return {ok:true,content:JSON.stringify({name:'Loopback observation comparison',target:runtime,
      prerequisites:['Loopback fixture only'],missing_conditions:[],success_criteria:'Record and compare fixture responses; no actual vulnerability asserted',
      cleanup:'Read-only requests; no cleanup',max_attempts:2,duration_ms:3000,
      steps:['baseline','verification'].map(mode=>({name:mode,description:'Fixture comparison',
        tool_id:'target-request',args_template:[JSON.stringify({url:runtime+'?mode='+mode,timeout_ms:500})],
        consumption:'none',expected_evidence:'Actual fixture HTTP response'}))})};
  }};
  const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
  app.use('/api/scan-tasks',scanRoutes(db));
  app.use('/api/pipelines/:id/verifications',verificationRoutes(db,dependencies));
  app.use((e,req,res,next)=>res.status(e.status || 500).json({status:'error',error:{message:e.message}}));
  const api=await listen(t,app);
  const request=async(path,body)=>{
    const response=await fetch(api+path,{method:body===undefined?'GET':'POST',
      headers:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    const value=await response.json();
    assert.ok(response.ok,JSON.stringify(value));
    return value.data;
  };
  const input={target:target+'/source/',runtime_target:runtime,authorization_confirmed:true,request_id:'flow_fixture_01'};
  const scan=await request('/api/scan-tasks/source-flow',input);
  assert.equal((await request('/api/scan-tasks/source-flow',input)).scan_task_id,scan.scan_task_id);
  await until(()=>['COMPLETED','PARTIAL','FAILED'].includes(db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id=?').get(scan.scan_task_id).status));
  assert.equal(creates,1);
  const final=await request('/api/scan-tasks/'+scan.scan_task_id);
  assert.equal(final.status,'COMPLETED',JSON.stringify(final));
  assert.equal(final.source_files.length,1);
  assert.equal(assistants.length,0,'upstream report path does not create a report Assistant');
  assert.ok(!calls.some(query=>/Assistant/.test(query)),'report import only reads task/subtask results');
  const rawReport=db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id=? AND result_type='raw_output'").all(scan.scan_task_id)
    .map(row=>JSON.parse(row.result_data)).find(raw=>raw.complete);
  assert.equal(rawReport.report,report,'complete task report is retained unchanged');
  const finding=final.results.find(row=>row.result_type==='source_finding');assert.ok(finding);
  const base='/api/pipelines/'+scan.pipeline_id+'/verifications';
  const item=await request(base,{finding_id:finding.id});
  const prepared=await request(base+'/'+item.id+'/prepare',{expected_revision:0});
  assert.equal(prepared.revision,1);assert.equal(generations,1);
  assert.equal(assistants.length,1,'only per-finding preparation creates the original Flow Assistant');
  let detail=await request(base+'/'+item.id);
  assert.equal(detail.payload_artifacts.collections[0].state,'ready');
  assert.equal(detail.execution_backend.pentagi_required_for_execution,false);
  const plan=detail.plans[0];
  const start={revision:1,fingerprint:plan.fingerprint,confirmed:true,request_id:'mock_execution_01'};
  const attempt=await request(base+'/'+item.id+'/start',start);
  assert.equal((await request(base+'/'+item.id+'/start',start)).id,attempt.id);
  await until(()=>db.prepare('SELECT state FROM finding_verification_attempts WHERE id=?').get(attempt.id).state==='completed');
  detail=await request(base+'/'+item.id);
  assert.equal(detail.attempts[0].steps.length,2);
  assert.equal(detail.attempts[0].evidence.length,2);
  assert.equal(detail.attempts[0].stop_confirmed,1);
  assert.notEqual(detail.summary.conclusion,'confirmed','transport completion is not a vulnerability verdict');
  assert.ok(requests.includes('/check?mode=baseline'));
  assert.ok(requests.includes('/check?mode=verification'));
  assert.equal(db.prepare('SELECT count(*) n FROM execution_attempts WHERE run_id=?').get(attempt.run_id).n,2);
  assert.equal(creates,1,'verification uses the platform executor, not a second PentAGI Flow');
  const lastCalls=calls.length;
  slow=true;
  const timed=await request(base+'/'+item.id+'/start',{...start,request_id:'mock_execution_02'});
  await until(()=>['failed','aborted','unknown'].includes(db.prepare('SELECT state FROM finding_verification_attempts WHERE id=?').get(timed.id).state));
  const failed=db.prepare('SELECT * FROM finding_verification_attempts WHERE id=?').get(timed.id);
  assert.equal(failed.stop_confirmed,1);
  assert.notEqual(failed.state,'unknown');
  assert.equal(calls.length,lastCalls,'execution and timeout handling do not call PentAGI');
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
});

test('source task creation requires scope acknowledgement and never replays a failed dispatch',async t=>{
  const db=getDb(':memory:');t.after(closeDb);
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('source_test','fixture','user',1)").run();
  const actor={sub:'source_test',role:'user'},input={target:'http://127.0.0.1/source/',request_id:'source_fixture_01'};
  assert.throws(()=>createSourceFlowTask(db,actor,input),/授权/);
  const row=createSourceFlowTask(db,actor,{...input,authorization_confirmed:true});
  let calls=0;
  await dispatchSourceFlow(db,row,async()=>{calls++;throw new Error('private detail');});
  const reused=createSourceFlowTask(db,actor,{...input,authorization_confirmed:true});
  await dispatchSourceFlow(db,reused,async()=>{calls++;});
  assert.equal(calls,1);
  assert.equal(db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id=?').get(row.scan_task_id).status,'FAILED');
  assert.throws(()=>createSourceFlowTask(db,actor,{...input,authorization_confirmed:true,target:'http://127.0.0.1/other/'}),/内容已变化/);
});
