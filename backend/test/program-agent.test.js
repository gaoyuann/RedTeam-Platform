import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import {readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {executeRun,requestAbort} from '../src/services/executionEngine.js';
import {generateSourceVerification,recordSourceVerification} from '../src/services/sourceVerification.js';
import {createProgramAgentState,observeProgramStep,validateProgramDecision,decideProgramNext,PROGRAM_AGENT_LIMITS} from '../src/services/programAgent.js';
import {runTargetRequest,parseTargetRequest} from '../src/tools/targetRequest.js';

async function listen(t,server) {
  const sockets=new Set();
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  server.listen(0,'127.0.0.1');
  await new Promise(r=>server.once('listening',r));
  t.after(async()=>{for(const socket of sockets) socket.destroy();await new Promise(r=>server.close(r));});
  return server.address().port;
}
const args=spec=>[JSON.stringify(spec)];
const baseState=()=>{
  const state=createProgramAgentState([]);
  observeProgramStep(state,{evidenceId:7,stepIndex:0,findingIds:[1],request:{url:'http://127.0.0.1:8090/'},
    result:{success:true,stdout:JSON.stringify({connected:true,response:'<a href="/next">next</a>'})}});
  return state;
};
test('TCP expect handles split UTF-8 prompts and waits for each menu before sending',async t=>{
  const received=[];
  const port=await listen(t,net.createServer(socket=>{
    const first=Buffer.from('选择>');socket.write(first.subarray(0,2));
    const timer=setTimeout(()=>socket.write(first.subarray(2)),30);socket.on('close',()=>clearTimeout(timer));
    socket.on('data',data=>{
      received.push(data.toString());
      if(received.length===1) socket.write('内容>');
      else socket.end('done');
    });
  }));
  const result=await runTargetRequest(args({url:'tcp://127.0.0.1:'+port,exchanges:[
    {expect:'选择>',send:'1\n',wait_ms:0},{expect:'内容>',send:'hello\n',wait_ms:0}]}));
  assert.equal(result.success,true,result.error);assert.deepEqual(received,['1\n','hello\n']);
  const observation=JSON.parse(result.stdout);
  assert.match(observation.response,/done/);
  assert.equal(observation.transcript.filter(e=>e.direction==='send').length,2);
  assert.match(Buffer.from(observation.transcript[0].data,'base64').toString(),/选择/);
});
test('missing TCP prompt stops input and cancellation ends a pending expect',async t=>{
  let received=0;
  const port=await listen(t,net.createServer(socket=>{socket.write('different');socket.on('data',data=>received+=data.length);}));
  const request={url:'tcp://127.0.0.1:'+port,exchanges:[{expect:'menu>',expect_timeout_ms:100,send:'must not send\n'}]};
  const result=await runTargetRequest(args(request));
  assert.equal(result.promptTimedOut,true);assert.equal(received,0);
  const controller=new AbortController(), pending=runTargetRequest(args({...request,exchanges:[{expect:'menu>',send:'x'}]}),{signal:controller.signal});
  setTimeout(()=>controller.abort(),25);
  assert.equal((await pending).aborted,true);assert.equal(received,0);
  assert.throws(()=>parseTargetRequest(args({...request,exchanges:[{expect:'.'.repeat(1025),send:'x'}]})),/expect/);
});
test('agent decisions require actual evidence, same origin and finding-specific linkage',()=>{
  const target='http://127.0.0.1:8090/',state=baseState();
  const value={action:'request',summary:'Follow the observed link',evidence_ids:[7],request:{url:target+'next'},
    finding_ids:[1],expected_evidence:'Compare the returned content'};
  assert.equal(validateProgramDecision(value,{target,findingIds:[1],state}).action,'request');
  assert.throws(()=>validateProgramDecision({...value,evidence_ids:[999]},{target,findingIds:[1],state}),/真实执行证据/);
  assert.throws(()=>validateProgramDecision({...value,request:{url:'http://127.0.0.1:18090/'}},{target,findingIds:[1],state}),/范围/);
  assert.throws(()=>validateProgramDecision({...value,finding_ids:[2]},{target,findingIds:[1],state}),/发现无效/);
  assert.throws(()=>validateProgramDecision({...value,assessments:[{finding_id:2,status:'candidate_supported',reason:'x',evidence_ids:[7]}]},{target,findingIds:[1,2],state}),/没有关联/);
  assert.throws(()=>validateProgramDecision({...value,assessments:[{finding_id:1,status:'confirmed',reason:'x',evidence_ids:[7]}]},{target,findingIds:[1],state}),/状态无效/);
});
test('agent rejects repeated requests, preserves remaining plan and stops calling unavailable models',async()=>{
  const target='http://127.0.0.1:8090/',state=baseState();
  const continueValue={action:'continue',summary:'Continue known steps',evidence_ids:[7]};
  const options={target,findingIds:[1],state};
  let calls=0;
  await decideProgramNext(options,{llm:async()=>{calls++;return {ok:false,error:'offline'};}});
  assert.equal(state.status,'unavailable');
  assert.equal(await decideProgramNext(options,{llm:async()=>{calls++;}}),null);assert.equal(calls,1);
  const fresh=baseState();fresh.fingerprints.push(fresh.fingerprints[0]);
  assert.throws(()=>validateProgramDecision({...continueValue,action:'request',request:{url:target},finding_ids:[1],expected_evidence:'x'},{target,findingIds:[1],state:fresh}),/两次/);
  assert.throws(()=>validateProgramDecision({...continueValue,action:'stop',reason:'evidence_collected'},{target,state:fresh,remainingSteps:[{step_index:1}]}),/未执行/);
  const budget=baseState();budget.decisions=PROGRAM_AGENT_LIMITS.decisions;
  await decideProgramNext({target,state:budget},{llm:async()=>{throw new Error('must not call');}});
  assert.equal(budget.status,'budget_exhausted');
  const invalid=baseState();
  await decideProgramNext({target,state:invalid},{llm:async()=>({ok:true,content:JSON.stringify({...continueValue,evidence_ids:[12345]})})});
  assert.equal(invalid.status,'invalid_decision');
});

async function dbFixture(t) {
  const db=getDb(':memory:');t.after(closeDb);
  const directory=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for(const name of (await readdir(directory)).sort()) {
    if(name.includes('import')) continue;
    const migration=await import(directory+name);(migration.default || migration.up)(db);
  }
  return db;
}
async function modelFixture(t,answer) {
  const old=Object.fromEntries(['LLM_API_KEY','LLM_BASE_URL','LLM_MODEL'].map(k=>[k,process.env[k]]));
  t.after(()=>{for(const [key,value] of Object.entries(old)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  const port=await listen(t,http.createServer(async(req,res)=>{
    let body='';for await(const data of req) body+=data;
    const context=JSON.parse(JSON.parse(body).messages[1].content);
    const value=await answer(context);
    if(value===null) return; // Used to exercise cancellation while the model is waiting.
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({choices:[{message:{content:JSON.stringify(value)}}]}));
  }));
  process.env.LLM_API_KEY='local-test-only';process.env.LLM_BASE_URL='http://127.0.0.1:'+port;process.env.LLM_MODEL='fixture';
}
async function planFixture(db,target,{findings=false,steps=1}={}) {
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status) VALUES ('scan',?,'source_scan','COMPLETED')").run(target);
  let findingId;
  if(findings) findingId=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('scan','source_finding',?)")
    .run(JSON.stringify({file:'input.c',start_line:2,end_line:2,code:'copy(buf,input);',title:'Check input length',snapshot_id:'frozen-1',source_sha256:'hash',reason:'Review bounds',preconditions:'Confirm actual input route'})).lastInsertRowid);
  const task={scan_task_id:'scan',target,status:'COMPLETED'};
  const plan={name:'Program verification',description:'Test observed entry',steps:Array.from({length:steps},(_,i)=>({
    name:'Request '+i,tool_id:'target-request',args_template:args({url:target+(i?'final':'')}),
    description:'Use observed entry',finding_ids:findingId?[findingId]:[],expected_evidence:'Record application response; requires review'
  }))};
  const generated=await generateSourceVerification(db,task,findingId?[findingId]:[],{adaptive:true,llm:async()=>({ok:true,content:JSON.stringify(plan)})});
  assert.equal(generated.ok,true,generated.error);
  db.prepare("INSERT INTO execution_runs(run_id,playbook_id,target,scan_task_id,status) VALUES ('run',?,?,'scan','PENDING')").run(generated.playbook_id,target);
  return {findingId,generated};
}
test('112 agent follows an observed HTTP route through the real engine and keeps source/evidence links',async t=>{
  const db=await dbFixture(t),visits=[];
  const port=await listen(t,http.createServer((req,res)=>{visits.push(req.url);res.end(req.url==='/next'?'comparison result':'<a href="/next">next</a>');}));
  const target='http://127.0.0.1:'+port+'/';
  const {findingId}=await planFixture(db,target,{findings:true});
  let modelCalls=0;
  await modelFixture(t,context=>{
    modelCalls++;
    assert.equal(context.scan_context[0].data.snapshot_id,'frozen-1');
    const last=context.execution_evidence.at(-1),id=last.evidence_id;
    if(modelCalls===1) {
      assert.match(last.observation.response,/href/);
      return {action:'request',summary:'Follow the link returned by the actual server',evidence_ids:[id],
        request:{url:target+'next'},finding_ids:[findingId],expected_evidence:'Observe linked route'};
    }
    assert.match(last.observation.response,/comparison result/);
    return {action:'stop',reason:'evidence_collected',summary:'Responses collected; memory issue remains unverified',evidence_ids:[id],
      assessments:[{finding_id:findingId,status:'inconclusive',reason:'Response alone cannot prove memory safety',evidence_ids:[id]}]};
  });
  const result=await executeRun('run');assert.equal(result.status,'COMPLETED',JSON.stringify(result));
  assert.deepEqual(visits,['/','/next']);assert.equal(modelCalls,2);
  const run=db.prepare("SELECT * FROM execution_runs WHERE run_id='run'").get();
  assert.equal(run.engine_type,'react');
  const summary=JSON.parse(run.final_summary).program_agent;
  assert.equal(summary.status,'evidence_collected');assert.equal(summary.assessments[0].review_required,true);
  const evidence=db.prepare("SELECT * FROM evidence_records WHERE run_id='run' ORDER BY id").all();
  assert.equal(evidence.length,2);
  assert.ok(JSON.parse(evidence[1].evidence_data).source_verification.finding_ids.includes(findingId));
  assert.equal(recordSourceVerification(db,findingId,{run_id:'run',status:'inconclusive',note:'Needs process diagnostics',evidence_ids:[evidence[1].id]},'reviewer').status,'inconclusive');
  // Same run is not sufficient: a generic step must not be used as proof for a source finding.
  db.prepare('UPDATE evidence_records SET evidence_data=? WHERE id=?').run(JSON.stringify({source_verification:{scan_task_id:'scan',finding_ids:[]}}),evidence[0].id);
  assert.throws(()=>recordSourceVerification(db,findingId,{run_id:'run',status:'supported',note:'wrong evidence',evidence_ids:[evidence[0].id]},'reviewer'),/没有关联/);
});
test('invalid model action never reaches the network; remaining reviewed steps still execute',async t=>{
  const db=await dbFixture(t),visits=[];
  const port=await listen(t,http.createServer((req,res)=>{visits.push(req.url);res.end('ok');}));
  const target='http://127.0.0.1:'+port+'/';await planFixture(db,target,{steps:2});
  let calls=0;
  await modelFixture(t,context=>{calls++;return {action:'request',summary:'bad scope',evidence_ids:[context.execution_evidence.at(-1).evidence_id],
    request:{url:'http://127.0.0.1:1/'},finding_ids:[],expected_evidence:'invalid'};});
  const result=await executeRun('run');assert.equal(result.status,'COMPLETED');
  assert.deepEqual(visits,['/','/final']);assert.equal(calls,1);
  const summary=JSON.parse(db.prepare("SELECT final_summary FROM execution_runs WHERE run_id='run'").get().final_summary);
  assert.equal(summary.program_agent.status,'invalid_decision');
});
test('operator abort cancels a live model request and prevents subsequent target requests',async t=>{
  const db=await dbFixture(t),visits=[];
  const port=await listen(t,http.createServer((req,res)=>{visits.push(req.url);res.end('ok');}));
  const target='http://127.0.0.1:'+port+'/';await planFixture(db,target,{steps:2});
  let started;const modelStarted=new Promise(r=>started=r);
  await modelFixture(t,()=>{started();return null;});
  const pending=executeRun('run');await modelStarted;requestAbort('run');
  const result=await pending;assert.equal(result.status,'ABORTED');assert.deepEqual(visits,['/']);
});
