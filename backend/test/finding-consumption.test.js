import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';
const guards=await import('../src/services/interventionGuards.js');
await mock.module('../src/services/interventionGuards.js',{namedExports:{...guards,applyBlueTeamPreExec:()=>({allowed:false,deniedReason:'fixture denies dispatch'})}});
const tools=await import('../src/tools/toolRunner.js');let toolCalls=0;
await mock.module('../src/tools/toolRunner.js',{namedExports:{...tools,runTool:async()=>{toolCalls++;throw new Error('blocked tool must never start');}}});
const {ensureVerification,saveVerificationPlan,verificationDetail,confirmAndStart}=await import('../src/services/findingVerification.js');
const {launchVerification}=await import('../src/services/findingVerificationRunner.js');
const {findingSignature}=await import('../src/services/findingPayload.js');
const {getPayloadById}=await import('../src/services/payloadLoader.js');
const {payloadVersion}=await import('../src/services/findingPayloads.js');
test('blocked tool keeps a planned payload reference but never claims actual consumption',async()=>{
 const db=getDb(':memory:');db.pragma('foreign_keys=ON');
 try {
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('blocked','fixture','user',1)").run();
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES('p','http://fixture.invalid/','completed','blocked','s','{}')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,status,created_by) VALUES('s','p','http://fixture.invalid/','web_scan','COMPLETED','blocked')").run();
  const id=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,severity,result_data) VALUES('s','sql_injection','high',?)").run(JSON.stringify({finding:'SQL injection at id'})).lastInsertRowid);
  const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='p'").get();const actor={sub:'blocked',role:'user'};const item=ensureVerification(db,pipeline,id);
  const payload={id:'blocked-payload',name:'SQL injection fixture',tags:['sqli'],version:1,applicability:{signature:findingSignature(db,db.prepare('SELECT * FROM scan_results WHERE id=?').get(id))},consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]}};
  db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(payload.id,payload.name,JSON.stringify(payload));
  saveVerificationPlan(db,pipeline,actor,item.id,{expected_revision:0,name:'Blocked fixture',target:pipeline.target,prerequisites:[],missing_conditions:[],success_criteria:'Observe specific effect',cleanup:'No cleanup',steps:[{name:'Check',tool_id:'target-request',args_template:[],consumption:'independent',payload_id:payload.id,payload_version:payloadVersion(getPayloadById(payload.id,db)),expected_evidence:'Specific response'}]});
  const d=verificationDetail(db,pipeline,item.id);const a=confirmAndStart(db,pipeline,actor,item.id,{revision:1,fingerprint:d.plans[0].fingerprint,request_id:'blocked',confirmed:true});
  await launchVerification(db,a,actor);
  const evidence=db.prepare('SELECT evidence_data FROM evidence_records WHERE run_id=?').get(a.run_id);const data=JSON.parse(evidence.evidence_data);
  assert.equal(toolCalls,0);assert.equal(data.payload_id,undefined);assert.equal(data.finding_verification.payload_consumed,false);assert.equal(data.finding_verification.tool_started,false);
 } finally {closeDb();}
});
