import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import http from 'node:http';
import net from 'node:net';
import {scanProgramAgent} from '../src/services/programScanAgent.js';
import {runTargetRequest} from '../src/tools/targetRequest.js';

function database(t) {
  const db=new Database(':memory:');t.after(()=>db.close());
  db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT); CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT)');
  return db;
}
async function listen(t,server) {
  server.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  return server.address().port;
}
const answer=value=>({ok:true,content:JSON.stringify(value)});

test('explicit source input delegates exclusively to CScan without the former scan model or local tools',async t=>{
  const db=database(t),parameters={input_kind:'source',source_url:'http://127.0.0.1:18090/code/'};
  const task={scan_task_id:'source',target:parameters.source_url,parameters:JSON.stringify(parameters)};let calls=0;
  const result=await scanProgramAgent(task,{db,parameters,
    snapshot:async()=>({snapshot_id:'fixture',connection_id:'task-http-source',files:[{path:'main.c'}],skipped:[],
      documents:[{path:'main.c',content:'int main(){return 0;}',start_line:1,end_line:1,sha256:'fixture'}],sourceDir:'/fixture'}),
    cscan:async source=>{calls++;return {snapshot_id:source.snapshot_id,flow_id:'1',findings:[],
      coverage:{reviewed_files:['main.c'],omitted_files:[],complete:true}};},
    runTool:()=>assert.fail('must not use local scan tools')},
    {llm:()=>assert.fail('must not use local scan model')});
  assert.equal(calls,1);assert.equal(result.outcomes.every(outcome=>outcome.success),true);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_coverage'").get().n,1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='application_observation'").get().n,0);
});

test('CScan source input retains its separately declared CGI runtime observation',async t=>{
  const db=database(t),visits=[];
  const port=await listen(t,http.createServer((req,res)=>{visits.push(req.url);res.end('Fixture CGI response');}));
  const target='http://127.0.0.1:'+port+'/',parameters={input_kind:'source',source_url:target+'source/'};
  const result=await scanProgramAgent({scan_task_id:'cgi',target,parameters:JSON.stringify(parameters)},
    {db,parameters,
      snapshot:async()=>({snapshot_id:'fixture',connection_id:'task-http-source',files:[{path:'handler.c'}],skipped:[],
        documents:[{path:'handler.c',content:'void handler(void) {}',start_line:1,end_line:1,sha256:'fixture'}],sourceDir:'/fixture'}),
      cscan:async source=>({snapshot_id:source.snapshot_id,flow_id:'2',findings:[],
        coverage:{reviewed_files:['handler.c'],omitted_files:[],complete:true}}),
      runTool:async(tool,args,options)=>{assert.equal(tool,'target-request');return runTargetRequest(args,options);}},
    {llm:()=>assert.fail('CScan source scanning must not call the platform scan model')});
  assert.deepEqual(visits,['/']);assert.equal(result.outcomes.every(outcome=>outcome.success),true);
  const observation=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='application_observation'").get().result_data);
  assert.equal(observation.url,target);assert.equal(observation.connected,true);
  const coverage=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='source_coverage'").get().result_data);
  assert.equal(coverage.runtime_target,target);
});

test('model disconnection preserves actual runtime inspection and incomplete coverage',async t=>{
  const db=database(t),port=await listen(t,http.createServer((req,res)=>res.end('fixture runtime')));
  const target='http://127.0.0.1:'+port+'/';let visits=0;
  const result=await scanProgramAgent({scan_task_id:'runtime',target},{db,parameters:{},projects:[],parseResults:()=>[],
    runTool:async(tool,args,options)=>{assert.equal(tool,'target-request');visits++;return runTargetRequest(args,options);}},
    {llm:async()=>{throw new Error('fixture model unavailable');}});
  assert.equal(visits,1);assert.ok(result.outcomes.some(outcome=>!outcome.success));
  const observation=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='application_observation'").get().result_data);
  assert.equal(observation.connected,true);assert.equal(observation.response,'fixture runtime');
  const coverage=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='program_coverage' ORDER BY id DESC").get().result_data);
  assert.equal(coverage.complete,false);
});

test('TCP program never invokes HTTP-only detectors and repeated mandatory inspection is rejected',async t=>{
  const db=database(t),port=await listen(t,net.createServer(socket=>socket.end('fixture menu>')));
  const target='tcp://127.0.0.1:'+port,calls=[];
  const runTool=async(tool,args,options)=>{calls.push(tool);return runTargetRequest(args,options);};
  await scanProgramAgent({scan_task_id:'tcp',target},{db,parameters:{},projects:[],parseResults:()=>[],runTool},
    {llm:async()=>answer({action:'nuclei',reason:'fixture unsupported scanner'})});
  assert.deepEqual(calls,['target-request']);
  assert.match(db.prepare("SELECT result_data FROM scan_results WHERE source_tool='program-agent' AND result_type='scan_error' ORDER BY id LIMIT 1").get().result_data,/HTTP 扫描器不适用于 TCP/);
  calls.length=0;
  await scanProgramAgent({scan_task_id:'duplicate',target},{db,parameters:{},projects:[],parseResults:()=>[],runTool},
    {llm:async()=>answer({action:'inspect',reason:'fixture repeat'})});
  assert.deepEqual(calls,['target-request']);
  assert.match(db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id='duplicate' AND result_type='scan_error' ORDER BY id DESC LIMIT 1").get().result_data,/已执行/);
});

test('cancelled program scanning never starts a tool or model decision',async t=>{
  const db=database(t),controller=new AbortController();controller.abort();
  let tools=0,models=0;
  await assert.rejects(scanProgramAgent({scan_task_id:'cancel',target:'http://127.0.0.1:8089/'},
    {db,parameters:{},signal:controller.signal,runTool:async()=>{tools++;},parseResults:()=>[]},
    {llm:async()=>{models++;}}),/取消/);
  assert.equal(tools,0);assert.equal(models,0);
});
