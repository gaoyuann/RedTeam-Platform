import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {fileURLToPath} from 'node:url';
import {runMigrations} from '../src/db/migrate.js';
import {ensureVerification,verificationDetail} from '../src/services/findingVerification.js';
import {generateVerificationCode} from '../src/services/findingVerificationCode.js';
import {readCodeArtifact} from '../src/services/verificationCodeArtifact.js';
import {parseResults} from '../src/services/scanResultParsers.js';
import {findingSignature} from '../src/services/findingPayload.js';
import {refreshPayloadIndex} from '../src/services/payloadLoader.js';

const answer={state:'ready',missing_information:[],files:[{filename:'repro.py',language:'python',source:'import sys\nvalue = sys.argv[1]\nprint("fixture probe detected" if value == "probe" else "normal input")'}],
  execution:{language:'python',entrypoint:'repro.py',baseline:{args:['normal'],stdin:''},probe:{args:['probe'],stdin:''},expected_output:'fixture probe detected',diagnostics:'none'},
  dependencies:[],run_conditions:['本地隔离模拟'],expected_results:['两组输入产生不同输出'],failure_reasons:['仅为模拟，实际环境未知'],remediation:['修复配置'],model_inferences:['基于扫描描述构造模拟']};
async function fixture(t,modelAnswer=answer) {
  const db=new Database(':memory:');db.pragma('foreign_keys=ON');t.after(()=>db.close());
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('reuse_owner','fixture','user',1),('reuse_other','fixture','user',1)").run();
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES('reuse_task','http://fixture.invalid/','completed','reuse_owner','reuse_scan','{}')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id,parameters) VALUES('reuse_scan','http://fixture.invalid/','web_scan','COMPLETED','reuse_owner','reuse_task','{}')").run();
  const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='reuse_task'").get(),actor={sub:'reuse_owner',role:'user'};
  let calls=0,lastContext;
  const deps={llm:async messages=>{calls++;lastContext=JSON.parse(messages.at(-1).content).untrusted_input;return {ok:true,content:JSON.stringify(modelAnswer)};}};
  const insert=(data,type='web_vuln',tool='nikto')=>{
    const id=Number(db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES(?,?,?,?,?)')
      .run('reuse_scan',type,JSON.stringify(data),'medium',tool).lastInsertRowid);
    return ensureVerification(db,pipeline,id);
  };
  const generate=(item,request,extra={})=>generateVerificationCode(db,pipeline,actor,item.id,
    {expected_revision:item.revision,request_id:request,authorization_confirmed:true,automatic_context:true,...extra},deps);
  return {db,pipeline,actor,insert,generate,get calls(){return calls;},get context(){return lastContext;}};
}

test('real Nikto finding reaches the model, saves code, and reuses it without another model request',async t=>{
  const f=await fixture(t);
  const parsed=parseResults('web_scan_nikto','+ Cookie PHPSESSID created without the secure flag.').find(r=>r.result_type==='web_vuln');
  const item=f.insert(parsed.result_data);
  const first=await f.generate(item,'nikto_first_request');
  assert.equal(first.state,'ready');assert.equal(f.calls,1);
  assert.equal(f.context.description,parsed.result_data.finding);
  assert.equal((await f.generate(item,'nikto_repeat_request')).id,first.id);assert.equal(f.calls,1);
  assert.equal((await f.generate(item,'nikto_first_request')).id,first.id);
  assert.equal((await f.generate(item,'nikto_force_request',{force_regenerate:true})).state,'ready');assert.equal(f.calls,2);
  const detail=verificationDetail(f.db,f.pipeline,item.id);
  assert.ok(detail.current_payload.items[0].execution_supported);
  assert.equal(detail.plans.length,0);assert.equal(detail.attempts.length,0);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
  const duplicate=f.insert(parsed.result_data);
  const copied=await f.generate(duplicate,'nikto_copy_request');
  assert.equal(copied.reused,true);assert.notEqual(copied.id,first.id);assert.equal(f.calls,2);
  assert.ok(copied.result.reuse.source_artifact_id);
  assert.equal(readCodeArtifact(f.db,duplicate.id,copied.id).files[0].source,answer.files[0].source);
  assert.equal((await f.generate(duplicate,'nikto_copy_request')).id,copied.id);
});

test('Cookie checking source saves intact, while literal credentials fail without replacing saved code',async t=>{
  const source=['import sys','from http.cookies import SimpleCookie','cookie = SimpleCookie()',
    'cookie["PHPSESSID"] = "<SESSION_TOKEN>"','cookie["PHPSESSID"]["secure"] = sys.argv[1] == "normal"',
    'print("normal input" if cookie["PHPSESSID"]["secure"] else "fixture probe detected")'].join('\n');
  const reply={...answer,files:[{filename:'repro.py',language:'python',source}]};
  const f=await fixture(t,reply),item=f.insert({finding:'Cookie PHPSESSID created without the secure flag.',code:source});
  const generated=await f.generate(item,'cookie_source_request');assert.equal(generated.state,'ready');
  assert.equal(f.context.source,source);assert.equal(readCodeArtifact(f.db,item.id,generated.id).files[0].source,source);
  assert.equal(verificationDetail(f.db,f.pipeline,item.id).current_payload.items[0].code,source);
  assert.equal((await f.generate(item,'cookie_source_reuse')).reused,true);assert.equal(f.calls,1);
  reply.files[0].source='cookie = "PHPSESSID=fixture-sensitive-session"';
  await assert.rejects(f.generate(item,'cookie_sensitive_request',{force_regenerate:true}),error=>
    error.status===422 && error.message==='生成源码含敏感字段，请移除凭据后重试');
  assert.equal(f.db.prepare("SELECT state FROM finding_verification_code WHERE request_id='cookie_sensitive_request'").get().state,'error');
  assert.equal(verificationDetail(f.db,f.pipeline,item.id).current_payload.items[0].code,source);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
});

test('description aliases and empty preferred fields work; genuinely missing input does not call a model',async t=>{
  const f=await fixture(t);
  for(const data of [{reason:' ',finding:'Cookie fixture lacks httponly'},
    {description:'Response header missing'}, {info:{name:'Header finding',description:'Scanner description'}},
    {title:'Legacy title only'}, {legacy_text:'Legacy finding description'}]) {
    assert.equal((await f.generate(f.insert(data),'alias_request_'+f.calls)).state,'ready');
    assert.ok(f.context.description.trim());
  }
  assert.equal(f.calls,5);
  const missing=await f.generate(f.insert({}),'empty_finding_request');
  assert.equal(missing.state,'needs_information');assert.equal(f.calls,5);
  await assert.rejects(f.generate(f.insert({title:'Fixture'}),'bad_force_request',{force_regenerate:'true'}),{status:400});
});

test('reuse rejects changed findings, environment, scope, malformed manifests and other users private artifacts',async t=>{
  const f=await fixture(t),item=f.insert({finding:'Cookie fixture lacks httponly'});
  const first=await f.generate(item,'scoped_first_request');
  f.db.prepare("UPDATE finding_verification_code SET created_by='reuse_other' WHERE id=?").run(first.id);
  await f.generate(item,'scoped_other_owner');assert.equal(f.calls,2);
  f.db.prepare("UPDATE scan_tasks SET parameters=? WHERE scan_task_id='reuse_scan'").run(JSON.stringify({runtime_environment:'Changed OS'}));
  const changed=await f.generate(item,'scoped_changed_env');assert.equal(f.calls,3);
  f.db.prepare('UPDATE finding_verification_code SET result=? WHERE id=?').run(JSON.stringify({...changed.result,execution:{}}),changed.id);
  await f.generate(item,'scoped_invalid_manifest');assert.equal(f.calls,4);
  const scoped={...f.pipeline,config:JSON.stringify({task_scope:{includes:['http://fixture.invalid/','http://other.invalid/']}})};
  let scopeCalls=0;
  const scopedResult=await generateVerificationCode(f.db,scoped,f.actor,item.id,{expected_revision:0,request_id:'scoped_changed_scope',automatic_context:true,authorization_confirmed:true},
    {llm:async()=>{scopeCalls++;return {ok:true,content:JSON.stringify(answer)};}});
  assert.equal(scopeCalls,1);assert.equal(scopedResult.reused,undefined);
  assert.equal(f.db.prepare("SELECT count(*) n FROM finding_verification_code WHERE request_id='scoped_changed_scope'").get().n,1);
  f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({finding:'Cookie fixture lacks secure'}),item.finding_id);
  const stale=verificationDetail(f.db,f.pipeline,item.id).current_payload.items[0];
  assert.equal(stale.stale,true);assert.equal(stale.execution_supported,false);
  await f.generate(item,'scoped_changed_finding');assert.equal(f.calls,5);
  assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
});

test('code workspace exposes compatible library payloads and skips generation; invalid or stale entries stay references',async t=>{
  const f=await fixture(t),item=f.insert({finding:'Cookie fixture lacks httponly'});
  const row=f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(item.finding_id);
  const payload={id:'reuse_library_fixture',name:{zh:'Cookie 配置验证'},applicability:{signature:findingSignature(f.db,row)},
    consumption:{type:'tool_args',tool_id:'target-request',args_template:['{"url":"<target>","method":"GET"}']}};
  const insert=f.db.prepare("INSERT INTO generated_payloads(payload_id,name,category,payload_type,payload_data,source,import_status,created_by) VALUES(?,?,'fixture','web',?,'ai_generated','accepted','reuse_owner')");
  insert.run(payload.id,'Cookie 配置验证',JSON.stringify(payload));refreshPayloadIndex();
  const detail=verificationDetail(f.db,f.pipeline,item.id),view=detail.current_payload.items[0];
  assert.equal(view.origin,'library');assert.equal(view.payload_id,payload.id);
  assert.equal(JSON.parse(view.code).tool_id,'target-request');assert.equal(view.execution_supported,false);
  const reused=await f.generate(item,'library_reuse_request');
  assert.equal(reused.state,'existing');assert.equal(reused.payload_id,payload.id);assert.equal(f.calls,0);
  assert.equal(f.db.prepare('SELECT count(*) n FROM finding_verification_code').get().n,0);
  // A manual request for local code can still generate a different representation.
  await f.generate(item,'library_local_request',{force_regenerate:true});assert.equal(f.calls,1);
  f.db.prepare('UPDATE generated_payloads SET payload_data=? WHERE payload_id=?').run(JSON.stringify({...payload,consumption:{...payload.consumption,args_template:['invalid request']}}),payload.id);
  refreshPayloadIndex();
  assert.equal(verificationDetail(f.db,f.pipeline,item.id).current_payload.items.some(v=>v.origin==='library'),false);
  f.db.prepare('UPDATE generated_payloads SET payload_data=? WHERE payload_id=?').run(JSON.stringify(payload),payload.id);refreshPayloadIndex();
  const other=f.insert({finding:'Different cookie finding'});
  assert.equal(verificationDetail(f.db,f.pipeline,other.id).current_payload.items.length,0);
  await f.generate(other,'library_missing_request');assert.equal(f.calls,2);
});
