import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {fileURLToPath} from 'node:url';

// Opt-in acceptance: real installed tool images and ephemeral loopback services.
// Only model replies are fixtures. Never touches the application's live database.
const enabled = process.env.REDTEAM_LIVE_TOOLS === '1';
process.env.DB_PATH = ':memory:';
let choices = 0, payloadCalls = 0;
await mock.module('../src/services/llmClient.js', {namedExports: {
  callLlm: async messages => {
    const system = messages[0].content;
    let input;
    try {input = JSON.parse(messages.at(-1).content);} catch {}
    if (input?.candidates) {
      const type = choices++ === 0 ? 'app_discovery' : 'web_scan';
      const candidate = input.candidates.find(c => c.scan_type === type);
      if (choices > 2) return {ok:true,content:JSON.stringify({action:'finish',reason:'Loopback checks completed'})};
      assert.ok(candidate, 'Expected '+type+' candidate');
      return {ok:true,content:JSON.stringify({action:'execute_check',check_id:candidate.check_id,
        evidence_id:candidate.source_record_id,reason:'Inspect the declared loopback fixture'})};
    }
    if (system.startsWith('为授权测试的单条漏洞')) return {ok:true,content:JSON.stringify({
      name:'Loopback header observation',target:input.target,prerequisites:[],missing_conditions:[],
      success_criteria:'Read the actual response header; a successful request alone does not establish a vulnerability',
      cleanup:'Read-only local fixture',steps:[{step_id:'observe_header',name:'Read fixture headers',
        tool_id:'target-request',args_template:[JSON.stringify({url:input.target,method:'GET'})],
        consumption:'none',expected_evidence:'Complete HTTP response headers'}],
    })};
    if (system.startsWith('你为授权范围内的漏洞验证生成')) {
      payloadCalls++;
      return {ok:true,content:JSON.stringify({name:'Loopback generated header request',tool_id:'target-request',
        args:[JSON.stringify({url:'<target>',method:'GET'})],tags:['headers']})};
    }
    if (input?.untrusted_input) return {ok:true,content:JSON.stringify({
      state:'ready',missing_information:[],files:[{filename:'repro.py',language:'python',
        source:"import sys\nprint('fixture-local-marker' if sys.argv[1:] == ['probe'] else 'normal fixture')\n"}],
      execution:{language:'python',entrypoint:'repro.py',baseline:{args:['normal'],stdin:''},
        probe:{args:['probe'],stdin:''},expected_output:'fixture-local-marker'},
      dependencies:[],run_conditions:['Local isolated fixture only'],expected_results:['Compare the fixture marker'],
      failure_reasons:['Runtime missing'],remediation:['Review real deployment separately'],input_facts:['Local fixture'],
      verified_facts:[],model_inferences:[],
    })};
    throw Error('Unexpected model request in live tools acceptance');
  },
  callLlmReact: async () => {throw Error('Reviewed plan must use the mechanical executor');},
}});

test('live tools: real scan -> displayed finding -> generated plan/payload -> bound request -> generated code -> real isolated run -> report',
  {skip:!enabled,timeout:180000}, async t => {
  const {getDb,closeDb} = await import('../src/db/connection.js');
  const {runMigrations} = await import('../src/db/migrate.js');
  const {default:pipelineRoutes} = await import('../src/routes/pipelines.js');
  const db = getDb(':memory:');
  let taskId;
  t.after(async()=>{
    const {cancelPipeline,runningPipelineCount} = await import('../src/services/pipelineEngine.js');
    if (taskId && runningPipelineCount()) cancelPipeline(taskId);
    for (let i=0;i<300 && runningPipelineCount();i++) await new Promise(resolve=>setTimeout(resolve,100));
    assert.equal(runningPipelineCount(),0,'The fixture worker must stop before its database closes');
    const {cancelVerification} = await import('../src/services/findingVerificationRunner.js');
    const active=()=>db.prepare("SELECT * FROM finding_verification_attempts WHERE state IN ('queued','running','cancelling')").all();
    for (const attempt of active()) await cancelVerification(db,attempt);
    for (let i=0;i<300 && active().length;i++) await new Promise(resolve=>setTimeout(resolve,100));
    assert.equal(active().length,0,'Verification workers must also stop before the fixture closes');
    closeDb();
  });
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('live-fixture','fixture','admin',1)").run();
  const requests = [];
  async function listen(server) {
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
    return 'http://127.0.0.1:'+server.address().port;
  }
  const target = await listen(http.createServer((req,res)=>{
    requests.push(req.method);
    res.setHeader('content-type','text/html');res.setHeader('server','Local-Acceptance-Fixture');
    res.statusCode = req.url === '/' ? 200 : 404;
    res.end(req.url === '/' ? '<html><title>Local acceptance</title>Fixture root only</html>' : 'Not found');
  })) + '/';
  const app = express(); app.use(express.json());
  app.use((req,res,next)=>{req.user={sub:'live-fixture',role:'admin'};next();});
  app.use('/api/pipelines',pipelineRoutes(db));
  app.use((error,req,res,next)=>res.status(error.status||500).json({error:{message:error.message}}));
  const endpoint = await listen(http.createServer(app));
  async function request(path,body,status=200) {
    const response = await fetch(endpoint+'/api/pipelines'+path,{
      method:body===undefined?'GET':'POST',headers:{'content-type':'application/json'},
      ...(body===undefined?{}:{body:JSON.stringify(body)}),
    });
    const result = await response.json();
    assert.equal(response.status,status,JSON.stringify(result));
    return result.data;
  }
  async function until(check) {
    for (let i=0;i<1400;i++) {const result=await check();if(result)return result;await new Promise(resolve=>setTimeout(resolve,100));}
    assert.fail('Live acceptance did not reach its expected state');
  }
  const task = await request('',{target,request_id:'live-loopback-create',config:{
    task_mode:'assessment',workflow_mode:'staged',authorization_confirmed:true,authorization_scope:target,
    task_scope:{includes:[target],excludes:[],execution_location:'scanner',discovery_budget:0},
  }},201);
  taskId = task.pipeline_id;
  await request('/'+task.pipeline_id+'/start',{},202);
  const pipeline=()=>db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(task.pipeline_id);
  await until(()=>!['pending','running'].includes(pipeline().status));
  assert.equal(pipeline().status,'completed',pipeline().error_message);
  const scans=db.prepare('SELECT scan_type,status FROM scan_tasks WHERE pipeline_id=?').all(task.pipeline_id);
  assert.ok(scans.some(s=>s.scan_type==='web_scan' && s.status==='COMPLETED'),JSON.stringify(scans));
  const findings=await request('/'+task.pipeline_id+'/results?view=scans&category=vulnerability');
  const finding=findings.scan_records.find(r=>r.source_tool==='nikto' && /X-Frame-Options/i.test(r.result_data));
  assert.ok(finding,'Real Nikto output must be persisted and returned by the scan results API');
  assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n,0,'The individual branch does not require a global plan');
  const root='/'+task.pipeline_id+'/verifications';
  const item=await request(root,{finding_id:finding.id});
  const path=root+'/'+item.id;
  await request(path+'/prepare',{expected_revision:0});
  let detail=await request(path);
  assert.equal(detail.revision,1,JSON.stringify(detail));
  const step=detail.plans[0].content.steps[0];
  const prepared=await request(path+'/payloads/prepare',{expected_revision:1,step_id:step.step_id});
  assert.equal(prepared.state,'generated');assert.equal(prepared.bound,false);assert.equal(payloadCalls,1);
  const reused=await request(path+'/payloads/prepare',{expected_revision:1,step_id:step.step_id});
  assert.equal(reused.payload_id,prepared.payload_id);assert.equal(payloadCalls,1);
  assert.equal((await request(path)).plans[0].content.steps[0].payload_id,null);
  await request(path+'/payloads/bind',{expected_revision:1,step_id:step.step_id,payload_id:prepared.payload_id,version:prepared.version});
  detail=await request(path);
  assert.equal(detail.revision,2);assert.equal(detail.readiness.ready,true,JSON.stringify(detail.readiness));
  const startBody={revision:detail.revision,fingerprint:detail.plans[0].fingerprint,confirmed:true,request_id:'live-bound-run'};
  const before=requests.length;
  const started=await request(path+'/start',startBody);
  assert.equal((await request(path+'/start',startBody)).id,started.id);
  let attempt=await until(async()=>{const d=await request(path);const a=d.attempts.find(a=>a.id===started.id);return a && !['queued','running','cancelling'].includes(a.state) && a;});
  assert.equal(attempt.state,'completed',JSON.stringify(attempt));
  assert.ok(requests.length>before,'Generated bound payload really reaches the local HTTP fixture');
  assert.ok(attempt.evidence.some(e=>e.evidence_data?.finding_verification?.payload_consumed===true));
  assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n,0);
  const code=await request(path+'/verification-code',{expected_revision:2,request_id:'live-code-generate',authorization_confirmed:true,
    description:'Only a local fixture marker comparison',affected_version:'fixture-v1',environment:'Isolated Python runtime',
    source:"print('fixture only')",authorization_scope:'Local isolated fixture only'});
  assert.equal(code.state,'ready',JSON.stringify(code));
  assert.equal(code.runtime_verified,false);
  assert.equal(db.prepare('SELECT count(*) n FROM finding_verification_attempts').get().n,1,'Generating code must not execute it');
  await request(path+'/code-plan',{expected_revision:2,artifact_id:code.id});
  detail=await request(path);
  assert.equal(detail.readiness.ready,true,JSON.stringify(detail.readiness));
  const simulation=await request(path+'/start',{revision:detail.revision,fingerprint:detail.plans[0].fingerprint,
    confirmed:true,request_id:'live-code-run'});
  attempt=await until(async()=>{const d=await request(path);const a=d.attempts.find(a=>a.id===simulation.id);return a && !['queued','running','cancelling'].includes(a.state) && a;});
  assert.equal(attempt.state,'completed',JSON.stringify(attempt));
  assert.equal(attempt.evidence.length,2);
  assert.ok(attempt.evidence.every(e=>e.evidence_data?.finding_verification?.artifact_consumed===true));
  assert.equal(attempt.summary.conclusion,'inconclusive','A local simulation never confirms a real target defect');
  const results=await request('/'+task.pipeline_id+'/results');
  const reportBody={run_id:results.execution.run?.run_id || '',source_fingerprint:results.source_fingerprint};
  await request('/'+task.pipeline_id+'/results/reports',{...reportBody,run_id:attempt.run_id},409);
  const report=await request('/'+task.pipeline_id+'/results/reports',reportBody,201);
  assert.ok(report.report.report_id);
  const exported=await fetch(endpoint+'/api/pipelines/'+task.pipeline_id+'/results/reports/'+report.report.report_id+'/export?format=json');
  assert.equal(exported.status,200);assert.ok((await exported.text()).includes(item.id));
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
});
