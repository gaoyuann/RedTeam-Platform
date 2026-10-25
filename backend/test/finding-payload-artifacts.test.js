import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import Database from 'better-sqlite3';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {runMigrations} from '../src/db/migrate.js';
import {createCscanClient,cscanConfig} from '../src/services/cscanClient.js';
import {ensureVerification,verificationDetail} from '../src/services/findingVerification.js';
import routes from '../src/routes/findingVerifications.js';
import {startPayloadCollection,startPythonRewrite,cancelPayloadArtifacts,payloadArtifactView,waitPayloadArtifacts} from '../src/services/findingPayloadArtifacts.js';
import {loadFindingContext} from '../src/services/findingPayload.js';

const actor={sub:'artifact_alice',role:'user'};
const original="printf 'fixture input'";
const result={summary:'Existing fixture script only',scripts:[{name:'Fixture input',language:'sh',content:original,source_type:'subtask',source_id:'s1',purpose:'Fixture observation',usage:'Review first',safety_notes:'Not proof of a source defect'}]};
const finding={evidence_origin:'cscan_report',cscan_flow_id:'91',file:'src/input.c',start_line:12,end_line:13,title:'Fixture bounds issue',reason:'No capacity check',cwe:'CWE-120',source_task_ids:['t1'],source_subtask_ids:['s1'],report_evidence:[{reason:'No capacity check'}]};
async function until(predicate) {for(let i=0;i<300;i++){if(predicate())return;await delay(5);}assert.fail('artifact operation did not reach the expected state');}
async function fixture(t) {
  const db=new Database(':memory:');db.pragma('foreign_keys=ON');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  for(const sub of ['artifact_alice','artifact_bob'])db.prepare("INSERT INTO users(username,password,role,is_active) VALUES(?,'fixture','user',1)").run(sub);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES('ap','http://fixture.invalid/source/','completed',?,'as','{}')").run(actor.sub);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id,parameters) VALUES('as','http://fixture.invalid/source/','source_scan','COMPLETED',?,'ap','{}')").run(actor.sub);
  const findingId=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES('as','source_finding',?,'high','cscan')").run(JSON.stringify(finding)).lastInsertRowid);
  db.prepare("INSERT INTO source_audits(scan_task_id,snapshot_id,connection_id,manifest,analysis,created_at) VALUES('as','report:as','cscan','{}',?,datetime('now'))")
    .run(JSON.stringify({engine:'cscan',cscan:{flow_id:'91',state:'finished',scan_complete:true},source_access_reported:'available'}));
  const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='ap'").get(),item=ensureVerification(db,pipeline,findingId);
  const state={assistants:[],logs:[],calls:[],creates:0,continuations:0,stops:0,reply:result,hold:false,loseCreate:false,crossFlow:false,taskReport:''};
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;
    const call=JSON.parse(body);state.calls.push(call);assert.equal(req.headers.authorization,'Bearer fixture-artifact');
    const id=String(call.variables.id),assistantId=String(call.variables.assistantId || '10');
    assert.equal(id,'91');
    let data;
    if(call.query.includes('CScanCreateAssistant')) {
      state.creates++;
      assert.match(call.query,/useAgents:false/);assert.match(call.variables.input,/不调用记忆代理/);
      state.assistants=[{id:'10',flowId:'91',status:'waiting',title:'Payload collection',useAgents:false}];
      state.logs.push({id:String(state.logs.length+1),flowId:'91',assistantId:'10',type:'input',message:call.variables.input,result:'',appendPart:false});
      if(state.loseCreate){state.loseCreate=false;res.destroy();return;}
      data={createAssistant:{assistant:state.assistants[0]}};
    } else if(call.query.includes('CScanCallAssistant')) {
      state.continuations++;assert.match(call.query,/useAgents:false/);
      state.logs.push({id:String(state.logs.length+1),flowId:'91',assistantId,type:'input',message:call.variables.input,result:'',appendPart:false});
      data={callAssistant:'success'};
    } else if(call.query.includes('CScanAssistantLogs')) {
      const last=state.logs.at(-1);
      if(!state.hold && last?.type==='input')state.logs.push({id:String(state.logs.length+1),flowId:'91',assistantId,type:'answer',message:JSON.stringify(state.reply),result:'',appendPart:false});
      data={assistantLogs:state.logs.map(row=>({...row,...(state.crossFlow?{flowId:'92'}:{})}))};
    } else if(call.query.includes('CScanAssistants'))data={assistants:state.assistants};
    else if(call.query.includes('CScanStopAssistant')) {state.stops++;data={stopAssistant:{id:assistantId,status:'finished'}};}
    else if(call.query.includes('CScanPayloadEvidence'))data={tasks:[{id:'t1',flowId:'91',result:state.taskReport,subtasks:[{id:'s1',result:'src/input.c line 12: No capacity check\nExisting fixture script:\n'+original}]}],terminalLogs:[],messageLogs:[]};
    else {assert.fail('collection must never create/stop a Flow or execute a tool');}
    res.setHeader('content-type','application/json');res.end(JSON.stringify({data}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const client=await createCscanClient(cscanConfig({CSCAN_API_URL:'http://127.0.0.1:'+server.address().port,CSCAN_API_TOKEN:'fixture-artifact',CSCAN_PROVIDER:'fixture'}));
  const dependencies={cscanClient:client,pollMs:2,collectionTimeoutMs:1500,rewriteTimeoutMs:1000,llm:async()=>({ok:true,content:JSON.stringify({python_code:"print('fixture input')",explanation:'Equivalent fixture text',usage:'Review before running'})})};
  t.after(async()=>{await cancelPayloadArtifacts(db,pipeline,item,actor,dependencies);await waitPayloadArtifacts(db,item);server.closeAllConnections();await new Promise(resolve=>server.close(resolve));db.close();});
  return {db,pipeline,item,state,client,dependencies,view:()=>payloadArtifactView(db,item),collect:input=>startPayloadCollection(db,pipeline,item,actor,input,dependencies)};
}

test('Assistant collection uses the same source Flow, persists provenance, reuses the assistant and supplies the Python rewrite',async t=>{
  const f=await fixture(t);f.state.hold=true;
  assert.equal(f.collect().collections[0].state,'collecting');
  await until(()=>f.state.creates===1);
  f.collect();await delay(10);assert.equal(f.state.creates,1);
  assert.equal(f.view().collections[0].state,'collecting','waiting plus a user log alone is not a completed answer');
  f.state.hold=false;await waitPayloadArtifacts(f.db,f.item);
  const collection=f.view().collections[0],script=collection.scripts[0];
  assert.equal(collection.state,'ready');assert.equal(collection.flow_id,'91');assert.equal(collection.runtime_verified,false);
  assert.equal(script.content,original);assert.equal(script.source_id,'s1');assert.equal(script.runtime_verified,false);
  assert.equal(f.db.prepare('SELECT COUNT(*) n FROM generated_payloads').get().n,0,'private collected scripts are not published to the global library');
  startPythonRewrite(f.db,f.pipeline,f.item,actor,{collection_id:collection.id,script_id:script.id,source_hash:script.source_hash},f.dependencies);
  await waitPayloadArtifacts(f.db,f.item);
  const rewritten=f.view().collections[0].rewrites[0];assert.equal(rewritten.state,'ready');assert.match(rewritten.python_code,/print/);assert.equal(rewritten.runtime_verified,false);
  const before=f.state.calls.length;f.collect();assert.equal(f.state.calls.length,before,'cached collection does not call the remote service');
  f.collect({refresh:true});await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.state.creates,1);assert.equal(f.state.continuations,1);
  assert.equal(f.view().collections.length,2,'refresh keeps previous collection and rewrite history');
  assert.ok(f.state.calls.every(call=>!call.query.includes('createFlow')&&!call.query.includes('stopFlow')));
});

test('a lost creation response is reconciled by its saved marker without creating a second assistant',async t=>{
  const f=await fixture(t);f.state.loseCreate=true;
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'uncertain');assert.equal(f.state.creates,1);
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'ready');assert.equal(f.state.creates,1);assert.equal(f.state.continuations,0);
});

test('Assistant can collect an unexecuted per-finding draft written by the scan Agent into its task report',async t=>{
  const f=await fixture(t);
  f.state.taskReport=[
    '## Fixture bounds issue','File: src/input.c','Line: 12-13','Evidence: No capacity check',
    'Payload-For: src/input.c:12-13','Payload-Status: draft','Payload-Language: sh','Payload-Content:',
    '```sh',original,'```','Payload-Prerequisites: Confirm the deployed version','Payload-Limitations: Not executed',
  ].join('\n');
  f.state.reply={summary:'Agent-generated draft, not executed',scripts:[{...result.scripts[0],source_type:'task',source_id:'t1',safety_notes:'Not executed; confirm deployed version'}]};
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  const collection=f.view().collections[0],script=collection.scripts[0];
  assert.equal(collection.state,'ready');assert.equal(script.source_type,'task');assert.equal(script.source_id,'t1');
  assert.equal(script.content,original);assert.equal(script.runtime_verified,false);
  const request=f.state.calls.find(call=>call.query.includes('CScanCreateAssistant'));
  assert.match(request.variables.input,/包括 Agent 为该漏洞生成但尚未执行的验证载荷草稿/);
  assert.match(request.variables.input,/Payload-For/);
  assert.equal(f.db.prepare('SELECT COUNT(*) n FROM execution_runs').get().n,0);
});

test('empty, unsupported and fabricated scripts are not treated as usable payloads',async t=>{
  const f=await fixture(t);f.state.reply={summary:'No prior payload',scripts:[]};
  f.collect();await waitPayloadArtifacts(f.db,f.item);assert.equal(f.view().collections[0].state,'empty');
  for(const change of [{content:'fabricated script'},{source_id:'unrelated'},{source_type:'assistant'}]) {
    f.state.reply={...result,scripts:[{...result.scripts[0],...change}]};
    f.collect({refresh:true});await waitPayloadArtifacts(f.db,f.item);
    assert.equal(f.view().collections[0].state,'error');assert.equal(f.view().collections[0].scripts.length,0);
  }
  assert.equal(f.db.prepare('SELECT COUNT(*) n FROM execution_runs').get().n,0);
});

test('ownership, source identity and runtime scanning state are checked before submitting or rewriting',async t=>{
  const f=await fixture(t);
  assert.throws(()=>startPayloadCollection(f.db,f.pipeline,f.item,{sub:'artifact_bob',role:'user'},{},f.dependencies),error=>error.status===403);
  f.db.prepare("UPDATE scan_tasks SET status='RUNNING' WHERE scan_task_id='as'").run();assert.throws(()=>f.collect(),/等待/);
  f.db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id='as'").run();
  f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({...finding,cscan_flow_id:'92'}),f.item.finding_id);assert.throws(()=>f.collect(),/对应关系/);
  assert.equal(f.state.calls.length,0);
  f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify(finding),f.item.finding_id);
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  const collection=f.view().collections[0],script=collection.scripts[0];
  assert.throws(()=>startPythonRewrite(f.db,f.pipeline,f.item,actor,{collection_id:collection.id,script_id:script.id,source_hash:'stale'},f.dependencies),/变化/);
  const context=loadFindingContext(f.db,f.item.finding_id,actor);
  assert.equal(context.details.file,'src/input.c');assert.equal(context.details.start_line,12);assert.equal(context.details.reason,'No capacity check');
});

test('cancellation stops only the collection assistant and late model replies cannot replace saved artifacts',async t=>{
  const f=await fixture(t);f.state.hold=true;f.collect();await until(()=>f.state.creates===1);
  await cancelPayloadArtifacts(f.db,f.pipeline,f.item,actor,f.dependencies);
  assert.equal(f.view().collections[0].state,'cancelled');assert.equal(f.state.stops,1);
  f.state.hold=false;f.collect({refresh:true});await waitPayloadArtifacts(f.db,f.item);
  const collection=f.view().collections[0],script=collection.scripts[0];let finish;
  const slow={...f.dependencies,llm:()=>new Promise(resolve=>{finish=resolve;})};
  startPythonRewrite(f.db,f.pipeline,f.item,actor,{collection_id:collection.id,script_id:script.id,source_hash:script.source_hash},slow);
  await until(()=>Boolean(finish));await cancelPayloadArtifacts(f.db,f.pipeline,f.item,actor,slow);
  finish({ok:true,content:JSON.stringify({python_code:"print('late')",explanation:'late',usage:'late'})});await delay(10);
  assert.equal(f.view().collections[0].rewrites[0].state,'interrupted');assert.equal(f.view().collections[0].rewrites[0].python_code,'');
});

test('source changes while the Assistant runs discard stale collection results',async t=>{
  const f=await fixture(t);f.state.hold=true;f.collect();await until(()=>f.state.creates===1);
  f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({...finding,reason:'Changed source evidence'}),f.item.finding_id);
  f.state.hold=false;await waitPayloadArtifacts(f.db,f.item);
  assert.notEqual(f.view().collections[0].state,'ready');assert.equal(f.view().collections[0].scripts.length,0);
});

test('cross-Flow Assistant logs are rejected by the real GraphQL client',async t=>{
  const f=await fixture(t);f.state.crossFlow=true;
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  assert.notEqual(f.view().collections[0].state,'ready');assert.equal(f.view().collections[0].scripts.length,0);
});

test('persisted interrupted collection and rewrite operations resume without duplicating remote requests',async t=>{
  const f=await fixture(t);f.collect();await waitPayloadArtifacts(f.db,f.item);
  let collection=f.view().collections[0];
  f.db.prepare("UPDATE finding_payload_collections SET state='collecting',scripts='[]' WHERE id=?").run(collection.id);
  assert.equal(f.view().collections[0].state,'interrupted');
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  collection=f.view().collections[0];assert.equal(collection.state,'ready');assert.equal(f.state.creates,1);assert.equal(f.state.continuations,0);
  const script=collection.scripts[0],input={collection_id:collection.id,script_id:script.id,source_hash:script.source_hash};
  startPythonRewrite(f.db,f.pipeline,f.item,actor,input,f.dependencies);await waitPayloadArtifacts(f.db,f.item);
  f.db.prepare("UPDATE finding_payload_rewrites SET state='rewriting',python_code='' WHERE collection_id=?").run(collection.id);
  assert.equal(f.view().collections[0].rewrites[0].state,'interrupted');
  startPythonRewrite(f.db,f.pipeline,f.item,actor,input,f.dependencies);await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].rewrites[0].state,'ready');assert.equal(f.view().collections[0].rewrites.length,1);
});

test('collection timeout retains its original Assistant for a bounded resume',async t=>{
  const f=await fixture(t);f.state.hold=true;
  startPayloadCollection(f.db,f.pipeline,f.item,actor,{}, {...f.dependencies,collectionTimeoutMs:80});await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'uncertain');assert.equal(f.state.creates,1);
  f.state.hold=false;f.collect();await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'ready');assert.equal(f.state.creates,1);assert.equal(f.state.continuations,0);
});

test('cancellation holds the operation lock until remote stop is confirmed',async t=>{
  const f=await fixture(t);f.state.hold=true;f.collect();await until(()=>f.state.creates===1);
  let release,stopping=false;
  const dependencies={...f.dependencies,cscanClient:{...f.client,stopAssistant:async(...args)=>{
    stopping=true;await new Promise(resolve=>{release=resolve;});return f.client.stopAssistant(...args);
  }}};
  const pending=cancelPayloadArtifacts(f.db,f.pipeline,f.item,actor,dependencies);await until(()=>stopping);
  f.collect({refresh:true});await delay(10);assert.equal(f.state.creates,1);assert.equal(f.state.continuations,0);
  release();await pending;assert.equal(f.view().collections[0].state,'cancelled');
});

test('invalid Python responses preserve original scripts and can be retried without re-collecting',async t=>{
  const f=await fixture(t);f.collect();await waitPayloadArtifacts(f.db,f.item);
  const collection=f.view().collections[0],script=collection.scripts[0],input={collection_id:collection.id,script_id:script.id,source_hash:script.source_hash};
  startPythonRewrite(f.db,f.pipeline,f.item,actor,input,{...f.dependencies,llm:async()=>({ok:true,content:'not JSON'})});await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].rewrites[0].state,'error');assert.equal(f.view().collections[0].scripts[0].content,original);
  startPythonRewrite(f.db,f.pipeline,f.item,actor,input,f.dependencies);await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].rewrites[0].state,'ready');assert.equal(f.state.creates,1);
});

test('task-scoped API exposes collection and rewrite state only to its owner, and migrations are repeatable',async t=>{
  const f=await fixture(t);
  assert.deepEqual(await runMigrations(f.db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url))),[]);
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user'] || actor.sub,role:'user'};next();});
  app.use('/tasks/:id/verifications',routes(f.db,f.dependencies));
  app.use((error,req,res,next)=>res.status(500).json({status:'error',error:{message:error.message}}));
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  const base='http://127.0.0.1:'+server.address().port+'/tasks/ap/verifications/'+f.item.id;
  const request=async(path,body,user=actor.sub)=>{const response=await fetch(base+path,{method:body?'POST':'GET',headers:{'content-type':'application/json','x-user':user},...(body?{body:JSON.stringify(body)}:{})});return {status:response.status,body:await response.json()};};
  assert.equal((await request('/payloads/collect',{expected_revision:0},'artifact_bob')).status,403);
  assert.equal((await request('/payloads/collect',{expected_revision:5})).status,409);
  assert.equal((await request('/payloads/collect',{expected_revision:0})).status,200);await waitPayloadArtifacts(f.db,f.item);
  const detail=(await request('')).body.data,collection=detail.payload_artifacts.collections[0],script=collection.scripts[0];
  assert.equal(collection.state,'ready');assert.equal(detail.attempts.length,0);
  assert.equal((await request('/payloads/python',{expected_revision:0,collection_id:collection.id,script_id:script.id,source_hash:script.source_hash})).status,200);
  await waitPayloadArtifacts(f.db,f.item);
  assert.equal((await request('')).body.data.payload_artifacts.collections[0].rewrites[0].state,'ready');
  assert.equal((await request('',undefined,'artifact_bob')).status,403);
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).attempts.length,0);
});


test('answer message fragments are consumed without treating terminal or input logs as a final reply',async t=>{
  const f=await fixture(t);f.state.hold=true;
  f.collect();await until(()=>f.state.creates===1);
  const text=JSON.stringify(result),cut=Math.floor(text.length/2);
  const log=(id,type,message,appendPart=false)=>({id,flowId:'91',assistantId:'10',type,message,result:'',appendPart});
  f.state.logs.push(log('2','terminal','not a JSON answer'),log('3','answer',text.slice(0,cut)),log('4','answer',text.slice(cut),true));
  f.state.assistants[0].status='finished';
  await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'ready');
  assert.equal(f.view().collections[0].scripts[0].content,original);
  assert.equal(f.state.creates,1);
});

test('non-JSON answer reports a format error promptly and is not mislabeled as a timeout',async t=>{
  const f=await fixture(t);f.state.hold=true;
  f.collect();await until(()=>f.state.creates===1);
  f.state.logs.push({id:'2',flowId:'91',assistantId:'10',type:'answer',message:'The requested materials are unavailable.',result:'',appendPart:false});
  f.state.assistants[0].status='finished';
  await waitPayloadArtifacts(f.db,f.item);
  const collection=f.view().collections[0];
  assert.equal(collection.state,'error');assert.match(collection.error_message,/JSON/);
  assert.doesNotMatch(collection.error_message,/超时/);
  assert.equal(collection.scripts.length,0);
  assert.equal(f.state.creates,1);
});

test('input and terminal output cannot satisfy a final answer; a later real answer resumes the same request',async t=>{
  const f=await fixture(t);f.state.hold=true;
  startPayloadCollection(f.db,f.pipeline,f.item,actor,{}, {...f.dependencies,collectionTimeoutMs:80});
  await until(()=>f.state.creates===1);
  f.state.logs.push({id:'2',flowId:'91',assistantId:'10',type:'terminal',message:JSON.stringify(result),result:JSON.stringify(result),appendPart:false});
  f.state.assistants[0].status='finished';
  await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'uncertain');
  assert.equal(f.view().collections[0].scripts.length,0);
  f.state.logs.push({id:'3',flowId:'91',assistantId:'10',type:'answer',message:JSON.stringify(result),result:'',appendPart:false});
  f.collect();await waitPayloadArtifacts(f.db,f.item);
  assert.equal(f.view().collections[0].state,'ready');
  assert.equal(f.state.creates,1);assert.equal(f.state.continuations,0);
});
