import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';
import {appendDeclaredTopologyEntries} from '../src/services/topologyWebEntries.js';

let calls=[], modelCalls=0, analysisCalls=0, failure=false, partial=false, hold=false, holding=false;
const defaultProbe='Nmap scan report for 192.0.2.10\nHost is up.\n8089/tcp open http TestHTTP 1.0';
let probeOutput=defaultProbe;
const runner=await import('../src/tools/toolRunner.js');
await mock.module('../src/tools/toolRunner.js',{namedExports:{...runner,runTool:async(tool,args,options={})=>{
  calls.push({tool,args});
  if (hold) {
    holding=true;
    return new Promise(resolve=>options.signal.addEventListener('abort',()=>resolve({success:false,aborted:true,
      exitCode:-2,stdout:'',stderr:'cancelled'}),{once:true}));
  }
  if (failure) return {success:false,exitCode:1,stdout:'',stderr:'fixture failure'};
  if (args.includes('--iflist')) return {success:true,exitCode:0,stdout:'INTERFACES\neth0 (eth0) 192.0.2.5/24 ethernet up 1500\nROUTES\n192.0.2.0/24 eth0 0',stderr:''};
  if (args.includes('-sn')) return {success:!partial,timedOut:partial,exitCode:partial?1:0,
    stdout:'Nmap scan report for 192.0.2.30\nHost is up (arp-response).',stderr:partial?'fixture timeout':''};
  return {success:true,exitCode:0,stdout:probeOutput,stderr:''};
}}});
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async()=>{modelCalls++;return {ok:false,error:'fixture boundary'};},callLlmReact:async()=>''}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async()=>{analysisCalls++;throw Error('discovery must never analyze');}}});
const {default:routes}=await import('../src/routes/pipelines.js');
const {default:topologyRoutes}=await import('../src/routes/topology.js');
const {cancelPipeline,runPipeline}=await import('../src/services/pipelineEngine.js');

async function fixture(t) {
  calls=[];modelCalls=analysisCalls=0;failure=partial=hold=holding=false;
  probeOutput=defaultProbe;
  const db=getDb(':memory:');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','unused','user'),('other','unused','user')").run();
  const app=express();app.use(express.json());
  app.use((req,res,next)=>{req.user={sub:req.headers['x-user'] || 'owner',role:'user'};next();});
  app.use('/api/pipelines',routes(db));app.use('/api/topology',topologyRoutes(db));
  app.use((error,req,res,next)=>res.status(error.status || 500).json({status:'error',error:{message:error.message}}));
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));closeDb();});
  const request=async(path,body,user='owner',method)=>{
    const res=await fetch(`http://127.0.0.1:${server.address().port}/api${path}`,{
      method:method || (body?'POST':'GET'),headers:{'content-type':'application/json','x-user':user},
      ...(body?{body:JSON.stringify(body)}:{})});
    return {code:res.status,body:await res.json()};
  };
  const create=async(target='192.0.2.10')=>{
    const created=await request('/pipelines',{target,config:{authorization_confirmed:true,
      task_scope:{includes:[target],excludes:[],execution_location:'scanner'}}});
    assert.equal(created.code,201);return created.body.data;
  };
  const wait=async predicate=>{
    for(let i=0;i<200;i++){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,10));}
    assert.fail('fixture operation did not finish');
  };
  const start=async parent=>{
    assert.equal((await request(`/pipelines/${parent.pipeline_id}/start`,{})).code,202);
    await wait(()=>db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(parent.pipeline_id).status!=='running');
    return db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(parent.pipeline_id);
  };
  return {db,request,create,start,wait};
}

test('new network tasks only discover assets, finish at topology selection, and never invoke vulnerability dispatch',async t=>{
  const {db,request,create,start}=await fixture(t);
  const parent=await create();
  assert.equal(parent.config.task_mode,'discovery');assert.equal(parent.config.scan_orchestrator,undefined);
  const finished=await start(parent);
  assert.equal(finished.status,'completed');assert.equal(JSON.parse(finished.result).next_action,'select_topology_target');
  assert.deepEqual(db.prepare('SELECT scan_type FROM scan_tasks').all().map(row=>row.scan_type),['port_scan']);
  assert.ok(calls.every(call=>call.tool==='nmap'));assert.ok(calls.some(call=>call.args.includes('-sV')));
  assert.equal(modelCalls,0);assert.equal(analysisCalls,0);
  assert.equal(db.prepare("SELECT count(*) n FROM pipeline_steps WHERE step_type!='scan'").get().n,0);
  assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
  assert.equal(db.prepare("SELECT count(*) n FROM task_checks WHERE state='planned'").get().n,0);
  const graph=(await request(`/topology/from-pipeline/${parent.pipeline_id}`)).body.data.topology;
  assert.ok(graph.nodes.some(node=>node.ip==='192.0.2.30'));
  assert.equal(graph.nodes.find(node=>node.ip==='192.0.2.10').services[0].port,'8089');
  assert.equal((await request('/topology/generate-from-scan',{scan_task_id:finished.scan_task_id})).code,200);
  assert.equal(modelCalls,0,'rendering discovery does not invoke AI either');
  assert.equal((await request(`/pipelines/${parent.pipeline_id}/start`,{})).code,400);
  assert.equal((await request(`/pipelines/${parent.pipeline_id}/approve`,{})).code,400);
  assert.equal((await request(`/pipelines/${parent.pipeline_id}/plan`,{})).code,409);
  const retry=await request(`/pipelines/${parent.pipeline_id}/retry-scan`,{request_id:'repeat-discovery-01'});
  assert.equal(retry.code,201);assert.equal(retry.body.data.config.task_mode,'discovery');
  assert.equal((await request(`/pipelines/${parent.pipeline_id}/retry-scan`,{request_id:'repeat-discovery-01'})).body.data.pipeline_id,retry.body.data.pipeline_id);
});

test('observed node creates an idempotent independent scan with correct target, scope, origin and result links',async t=>{
  const {db,request,create,start}=await fixture(t);
  const parent=await create();await start(parent);
  const graph=(await request(`/topology/from-pipeline/${parent.pipeline_id}`)).body.data.topology;
  const neighbor=graph.nodes.find(node=>node.ip==='192.0.2.30');
  assert.equal(neighbor.scan.eligible,false,'topology-only neighbors cannot expand the parent task');
  const body={target:neighbor.ip,request_id:'selected-node-scan-01',
    topology_source:{pipeline_id:parent.pipeline_id,node_id:neighbor.id},
    config:{task_mode:'assessment',authorization_confirmed:true,
      task_scope:{includes:[neighbor.ip],excludes:[],execution_location:'scanner'}}};
  const created=await request('/pipelines',body);assert.equal(created.code,201,JSON.stringify(created.body));
  const child=created.body.data;
  assert.notEqual(child.pipeline_id,parent.pipeline_id);assert.equal(child.target,neighbor.ip);
  assert.equal(child.config.scan_orchestrator.mode,'react');assert.equal(child.config.topology_source.node_id,neighbor.id);
  assert.deepEqual(child.config.task_scope.includes,[neighbor.ip]);
  assert.equal(db.prepare('SELECT target FROM pipelines WHERE pipeline_id=?').get(parent.pipeline_id).target,parent.target);
  assert.equal((await request('/pipelines',body)).body.data.pipeline_id,child.pipeline_id);
  assert.equal((await request('/pipelines',{...body,target:'192.0.2.40'})).code,409);
  assert.equal((await request('/pipelines',{...body,request_id:'wrong-node-target',target:'192.0.2.40'})).code,409);
  assert.equal((await request('/pipelines',{...body,request_id:'missing-node-source',topology_source:{...body.topology_source,node_id:'manual-fake'}})).code,409);
  assert.equal((await request('/pipelines',{...body,request_id:'unconfirmed-node',config:{...body.config,authorization_confirmed:false}})).code,400);
  assert.equal((await request('/pipelines',{...body,request_id:'wide-node-scope',config:{...body.config,task_scope:{includes:['192.0.2.0/24']}}})).code,400);
  assert.equal((await request('/pipelines',{...body,request_id:'foreign-node-source'},'other')).code,404);
  const query=`/topology/linked-tasks?pipeline_id=${parent.pipeline_id}&node_id=${neighbor.id}`;
  let linked=(await request(query)).body.data;assert.equal(linked.length,1);assert.equal(linked[0].pipeline_id,child.pipeline_id);
  assert.equal((await request(query,undefined,'other')).code,404);
  const edited=await request(`/pipelines/${child.pipeline_id}`,{config:{timeout:60}},'owner','PUT');
  assert.equal(edited.code,200);
  const editedConfig=JSON.parse(edited.body.data.config);
  assert.equal(editedConfig.topology_source.node_id,neighbor.id);
  assert.equal(editedConfig.task_mode,'assessment');
  db.prepare("INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,status,created_by) VALUES ('child-results',?,?,'web_scan','PARTIAL','owner')").run(child.pipeline_id,child.target);
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES ('child-results','web_vuln','{}','high','nikto')").run();
  db.prepare("UPDATE pipelines SET status='failed' WHERE pipeline_id=?").run(child.pipeline_id);
  linked=(await request(query)).body.data;assert.equal(linked[0].finding_count,1);assert.equal(linked[0].status,'failed');
  assert.equal((await request(`/pipelines/${child.pipeline_id}`,{config:{timeout:90}},'owner','PUT')).code,409,
    'finished assessment configuration remains frozen');
});

test('node service selection requires exact discovered protocol and port; standalone evidence also retains its source',async t=>{
  const {db,request,create,start}=await fixture(t);
  const parent=await create();const finished=await start(parent);
  const graph=(await request(`/topology/from-pipeline/${parent.pipeline_id}`)).body.data.topology;
  const node=graph.nodes.find(node=>node.ip==='192.0.2.10');
  const body={target:'http://192.0.2.10:8089/',topology_source:{pipeline_id:parent.pipeline_id,node_id:node.id},
    config:{task_mode:'assessment',authorization_confirmed:true}};
  assert.equal((await request('/pipelines',{...body,target:'https://192.0.2.10:8089/'})).code,409);
  assert.equal((await request('/pipelines',{...body,target:'http://192.0.2.10:9999/'})).code,409);
  const child=await request('/pipelines',body);assert.equal(child.code,201,JSON.stringify(child.body));
  assert.deepEqual(child.body.data.config.task_scope.includes,[body.target]);
  const standalone=await request('/topology/generate-from-scan',{scan_task_id:finished.scan_task_id});
  const sourceNode=standalone.body.data.topology.nodes.find(node=>node.ip==='192.0.2.10');
  const independent=await request('/pipelines',{...body,topology_source:{scan_task_id:finished.scan_task_id,node_id:sourceNode.id}});
  assert.equal(independent.code,201,JSON.stringify(independent.body));
  const linked=await request(`/topology/linked-tasks?scan_task_id=${finished.scan_task_id}&node_id=${sourceNode.id}`);
  assert.equal(linked.body.data[0].pipeline_id,independent.body.data.pipeline_id);
});

test('discovery retains partial evidence, handles failure and cancellation, and never advances to analysis',async t=>{
  const {db,request,create,start,wait}=await fixture(t);
  partial=true;const incomplete=await start(await create());
  assert.equal(incomplete.status,'completed');assert.equal(JSON.parse(incomplete.result).completeness,'incomplete');
  partial=false;failure=true;const failed=await start(await create());assert.equal(failed.status,'failed');
  failure=false;hold=true;const parent=await create();
  assert.equal((await request(`/pipelines/${parent.pipeline_id}/start`,{})).code,202);
  await wait(()=>holding);assert.equal(cancelPipeline(parent.pipeline_id).ok,true);
  await wait(()=>db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(parent.pipeline_id).status!=='running');
  assert.equal(db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(parent.pipeline_id).status,'cancelled');
  assert.equal(analysisCalls,0);assert.equal(modelCalls,0);
});

test('historical assessment tasks keep their dispatch and are not reinterpreted as discovery',async t=>{
  const {db,request}=await fixture(t);
  const program=await request('/pipelines',{target:'tcp://192.0.2.20:8091',config:{test_type:'program',input_kind:'runtime'}});
  assert.equal(program.code,201);assert.equal(program.body.data.config.task_mode,undefined);
  assert.equal(program.body.data.config.scan_orchestrator.mode,'react','runtime program mode keeps its previous dispatch');
  const created=await request('/pipelines',{target:'http://fixture.invalid/',config:{task_mode:'assessment'}});
  assert.equal(created.code,201);assert.equal(created.body.data.config.scan_orchestrator.mode,'react');
  const parent=created.body.data;
  db.prepare('UPDATE pipelines SET config=? WHERE pipeline_id=?').run(JSON.stringify({scan_orchestrator:{version:1,mode:'react'},
    task_scope:{includes:[parent.target],excludes:[],execution_location:'scanner'}}),parent.pipeline_id);
  const result=await runPipeline(parent.pipeline_id);
  assert.equal(result.ok,false);assert.equal(modelCalls,1);assert.equal(calls.length,0);
  assert.equal(JSON.parse(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(parent.pipeline_id).config).task_mode,undefined);
});

test('topology selection preserves declared Web host, path and query for task and standalone scans',async t=>{
  const {request,create,start}=await fixture(t);
  for (const hostname of ['site.example.test','192.0.2.10']) {
    const target=`https://${hostname}:8443/app/lookup?item=one%20two`;
    probeOutput=`Nmap scan report for ${hostname==='192.0.2.10'?hostname:hostname+' (192.0.2.10)'}\nHost is up.\n8443/tcp open ssl/http TestHTTP`;
    const parent=await create(target);const finished=await start(parent);
    const graph=(await request(`/topology/from-pipeline/${parent.pipeline_id}`)).body.data.topology;
    const node=graph.nodes.find(node=>node.ip==='192.0.2.10');
    assert.equal(node.entries[0].value,target);assert.equal(node.entries[0].state,'declared');
    assert.ok(!graph.nodes.filter(other=>other.ip==='192.0.2.30').some(other=>other.entries.some(entry=>entry.value===target)),
      'original application is never attached to another discovered host');
    const body={target,topology_source:{pipeline_id:parent.pipeline_id,node_id:node.id},
      config:{task_mode:'assessment',authorization_confirmed:true,task_scope:{includes:[target],excludes:[]}}};
    const child=await request('/pipelines',body);
    assert.equal(child.code,201,JSON.stringify(child.body));assert.equal(child.body.data.target,target);
    assert.deepEqual(child.body.data.config.task_scope.includes,[target]);
    assert.equal(child.body.data.config.topology_source.host,'192.0.2.10');
    for (const altered of [target.replace('/app/lookup','/other/'),target.replace('https:','http:'),
      target.replace(':8443',':9999'),target.replace(hostname,'unrelated.example.test')]) {
      assert.equal((await request('/pipelines',{...body,target:altered,config:{...body.config,task_scope:{includes:[altered]}}})).code,409,
        `unobserved application must be rejected: ${altered}`);
    }
    const standalone=(await request('/topology/generate-from-scan',{scan_task_id:finished.scan_task_id})).body.data.topology;
    const standaloneNode=standalone.nodes.find(node=>node.ip==='192.0.2.10');
    assert.equal(standaloneNode.entries[0].value,target);
    const second=await request('/pipelines',{...body,topology_source:{scan_task_id:finished.scan_task_id,node_id:standaloneNode.id}});
    assert.equal(second.code,201,JSON.stringify(second.body));assert.equal(second.body.data.target,target);
  }
});

test('discovery start blocks overlapping active tasks and tools whose stop is unconfirmed',async t=>{
  const {db,request,create,start}=await fixture(t);
  const first=await create();const second=await create();
  db.prepare("UPDATE pipelines SET status='running' WHERE pipeline_id=?").run(first.pipeline_id);
  let blocked=await request(`/pipelines/${second.pipeline_id}/start`,{});
  assert.equal(blocked.code,409);assert.match(blocked.body.error.message,/活动任务/);
  assert.equal(db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(second.pipeline_id).status,'created');
  assert.equal(calls.length,0);assert.equal(modelCalls,0);
  db.prepare("UPDATE pipelines SET status='failed' WHERE pipeline_id=?").run(first.pipeline_id);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,status,created_by) VALUES ('busy-scan',?,'192.0.2.10','port_scan','FAILED','owner')").run(first.pipeline_id);
  db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,outcome,started_at) VALUES ('busy-tool','busy-scan','nmap','port_scan','failed',?,?)")
    .run(JSON.stringify({stopped:false}),new Date().toISOString());
  blocked=await request(`/pipelines/${second.pipeline_id}/start`,{});
  assert.equal(blocked.code,409);assert.match(blocked.body.error.message,/停止未确认/);
  assert.equal(calls.length,0);
  assert.equal(db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(second.pipeline_id).status,'created');
  const unrelated=await start(await create('192.0.2.99'));
  assert.equal(unrelated.status,'completed','a non-overlapping target remains usable');
  db.prepare("UPDATE scan_tool_runs SET outcome=? WHERE tool_run_id='busy-tool'").run(JSON.stringify({stopped:true}));
  const resumed=await start(second);assert.equal(resumed.status,'completed');
});

test('declared Web entries never infer aliases across scans or reinterpret source access as application evidence',()=>{
  const target='https://site.example.test:8443/app/';
  const graph=()=>({nodes:[{id:'node',ip:'192.0.2.10',hostName:'site.example.test'}]});
  const observation={scan_task_id:'other',result_type:'host_discovery',
    result_data:JSON.stringify({host:'192.0.2.10',hostName:'site.example.test',status:'up'})};
  const scan={scan_task_id:'current',scan_type:'port_scan',target};
  assert.equal(appendDeclaredTopologyEntries(graph(),[scan],[observation]).nodes[0].entries,undefined,
    'matching display hostname alone cannot establish an alias');
  const matched={...observation,scan_task_id:'current'};
  assert.equal(appendDeclaredTopologyEntries(graph(),[scan],[matched]).nodes[0].entries[0].value,target);
  assert.equal(appendDeclaredTopologyEntries(graph(),[{...scan,scan_type:'source_scan'}],[matched]).nodes[0].entries,undefined);
  assert.equal(appendDeclaredTopologyEntries(graph(),[scan],[{...matched,result_data:JSON.stringify({
    host:'192.0.2.10',hostName:'site.example.test',traceTarget:'192.0.2.30'})}]).nodes[0].entries,undefined);
});
