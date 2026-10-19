import {cscanFixture} from './helpers/cscanFixture.js';
import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import net from 'node:net';
import {mkdtemp,mkdir,writeFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';

// CScan and the plan model use protocol fixtures. Collection, task APIs,
// approval and HTTP/TCP execution are real. Unrelated port discovery is stubbed.
const sourceModule=await import('../src/services/sourceSnapshot.js');
let snapshotRoot;
await mock.module('../src/services/sourceSnapshot.js',{namedExports:{...sourceModule,
  createSourceSnapshot:(connection,options)=>sourceModule.createSourceSnapshot(connection,{...options,snapshotRoot})}});
const toolModule=await import('../src/tools/toolRunner.js');
await mock.module('../src/tools/toolRunner.js',{namedExports:{...toolModule,
  runTool:async(tool,args,options)=>tool==='nmap' ? {success:true,exitCode:0,stdout:'<nmaprun></nmaprun>',stderr:'',executionMode:'fixture'}
    : tool==='target-request' ? toolModule.runTool(tool,args,options) : assert.fail('Source scanning must use CScan, not '+tool)}});
const {default:pipelineRoutes}=await import('../src/routes/pipelines.js');
const {default:scanRoutes}=await import('../src/routes/scans.js');
const {ensureVerification,verificationDetail}=await import('../src/services/findingVerification.js');

async function listen(t,server) {
  server.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));});
  return server.address().port;
}
async function until(db,id,status) {
  const deadline=Date.now()+15000;
  while(Date.now()<deadline) {
    const pipeline=db.prepare('SELECT status,error_message FROM pipelines WHERE pipeline_id=?').get(id);
    if(pipeline.status===status) return;
    assert.notEqual(pipeline.status,'failed',pipeline.error_message);
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.fail('workflow did not reach '+status);
}

for(const [mode,protocol] of [['source_assisted','http'],['program_dynamic','tcp']]) {
  test(`offline ${mode} ${protocol}: CScan protocol -> generated draft -> approval -> actual request evidence`,
    async t=>{
    const cscan=await cscanFixture(t,[{file:'input.c',start_line:3,title:'Fixture input bounds',
      reason:'Test-owned fixed buffer copy candidate',preconditions:'Runtime route linkage remains to be reviewed',cwe:'CWE-120',severity:'high'}]);
    const root=await mkdtemp(join(tmpdir(),'rt-workflow-'));t.after(()=>rm(root,{recursive:true,force:true}));
    snapshotRoot=join(root,'snapshots');const sourceDir=join(root,'source');await mkdir(sourceDir);
    await writeFile(join(sourceDir,'input.c'),'#include <string.h>\nvoid copy_input(char *input) {\n char buffer[8]; strcpy(buffer,input);\n}\n');
    const effects=[];
    const runtimePort=await listen(t,protocol==='http' ? http.createServer((req,res)=>{
      if(req.url.startsWith('/check?')) effects.push(req.url);
      res.end('fixture response '+req.url);
    }) : net.createServer(socket=>{
      socket.write('fixture menu>');socket.on('data',data=>{effects.push(data.toString());socket.end('fixture echo:'+data);});
    }));
    const target=(protocol==='http'?'http://':'tcp://')+'127.0.0.1:'+runtimePort+(protocol==='http'?'/':'');
    const configFile=join(root,'connections.json');
    await writeFile(configFile,JSON.stringify([{id:'offline',kind:'local',source_root:sourceDir,targets:[target],architecture:'fixture'}]));
    const keys=['SOURCE_SCAN_CONNECTIONS_FILE','LLM_API_KEY','LLM_BASE_URL','LLM_MODEL'];
    const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
    t.after(()=>{for(const [key,value] of Object.entries(previous)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
    process.env.SOURCE_SCAN_CONNECTIONS_FILE=configFile;
    let generatedCalls=0;
    const modelPort=await listen(t,http.createServer(async(req,res)=>{
      let raw='';for await(const chunk of req) raw+=chunk;
      const messages=JSON.parse(raw).messages,system=messages[0].content;
      let output;
      if(system.includes('靶场验证预案设计者')) {
        generatedCalls++;
        const context=JSON.parse(messages[1].content),id=context.findings[0].id;
        output={name:'Offline input comparison',steps:['baseline','verification'].map((phase,index)=>({
          name:phase,tool_id:'target-request',phase,finding_ids:[id],
          args_template:[JSON.stringify(protocol==='http' ? {url:target+'check?value='+(index?'boundary':'normal')}
            : {url:target,exchanges:[{expect:'fixture menu>',send:(index?'boundary':'normal')+'\n'}]})],
          description:'Fixture comparison, not a real exploit',expected_evidence:'Compare actual fixture echo; not proof of memory corruption'}))};
        output.steps[1].criteria={kind:'response_contains',value:'boundary',limitations:'A fixture echo is not proof of a source defect'};
        output.required_conditions=['Confirm the deployed program uses the frozen source'];
      } else output={tech_stack:[],attack_surface:[],risk_assessment:[],recommended_strategy:[]};
      res.setHeader('content-type','application/json');res.end(JSON.stringify({choices:[{message:{content:JSON.stringify(output)}}]}));
    }));
    process.env.LLM_API_KEY='fixture-only';process.env.LLM_BASE_URL='http://127.0.0.1:'+modelPort;process.env.LLM_MODEL='fixture';
    const db=getDb(':memory:');t.after(closeDb);
    const migrations=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
    for(const name of (await readdir(migrations)).sort()) {
      if(name.includes('import')) continue;
      const migration=await import(migrations+name);(migration.default || migration.up)(db);
    }
    for(const [user,role] of [['alice','user'],['admin','admin']])
      db.prepare('INSERT OR IGNORE INTO users(username,password,role) VALUES (?,\'fixture\',?)').run(user,role);
    const app=express();app.use(express.json(),(req,res,next)=>{const sub=req.headers['x-user'] || 'alice';req.user={sub,role:sub==='admin'?'admin':'user'};next();});
    app.use('/pipelines',pipelineRoutes(db));app.use('/scans',scanRoutes(db));
    const apiPort=await listen(t,http.createServer(app));
    const request=async(path,body,user='alice',method='POST')=>{
      const response=await fetch('http://127.0.0.1:'+apiPort+path,{method,headers:{'content-type':'application/json','x-user':user},body:JSON.stringify(body)});
      const result=await response.json();assert.ok(response.ok,JSON.stringify(result));return result.data;
    };
    const pipeline=await request('/pipelines',{target,config:{scan_mode:mode,source_connection_id:'offline',
      authorization_confirmed:true,authorization_scope:target,auto_execute:true}});
    const id=pipeline.pipeline_id;await request('/pipelines/'+id+'/start',{});await until(db,id,'awaiting_approval');
    const task=db.prepare('SELECT * FROM scan_tasks').get();
    assert.equal(task.status,'COMPLETED',task.error_message);
    const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
    assert.equal(coverage.files,1);assert.equal(coverage.ai_complete,true);
    assert.equal(coverage.engine,'cscan');assert.equal(coverage.cscan_complete,true);assert.equal(cscan.counts.created,1);
    const findings=db.prepare("SELECT id,result_data FROM scan_results WHERE result_type='source_finding'").all();assert.ok(findings.length);
    const finding=findings.find(row=>JSON.parse(row.result_data).title==='Fixture input bounds');assert.ok(finding);
    const taskPipeline=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
    const verification=ensureVerification(db,taskPipeline,finding.id);
    const detail=verificationDetail(db,taskPipeline,verification.id);
    assert.equal(detail.eligible,true,'CScan source finding is eligible for the F08 verification workflow');
    assert.equal(detail.finding.id,finding.id);assert.equal(detail.default_target,target);
    assert.deepEqual(JSON.parse(detail.finding.result_data).tools,['cscan']);
    assert.equal(detail.summary.conclusion,'pending','importing a finding never confirms a runtime vulnerability');
    assert.equal(effects.length,0,'no verification request before plan approval');
    const generated=await request('/scans/'+task.scan_task_id+'/generate-playbook',{finding_ids:[finding.id],demonstration:true,adaptive:false});
    const sources=await request('/pipelines/'+id+'/plan/sources',undefined,'alice','GET');
    assert.deepEqual(sources.map(source=>source.playbook_id),[generated.playbook_id]);
    const draft=await request('/pipelines/'+id+'/plan',{playbook_id:generated.playbook_id});assert.equal(draft.content.steps.length,2);
    const submitted=await request('/pipelines/'+id+'/plan/submit',{revision:draft.revision});
    await request('/pipelines/'+id+'/plan/approve',{revision:submitted.revision},'admin');await until(db,id,'completed');
    assert.equal(effects.length,2);assert.equal(generatedCalls,1);
    const run=db.prepare('SELECT * FROM execution_runs').get();assert.equal(run.status,'COMPLETED');assert.equal(run.engine_type,'mechanical');
    const evidence=db.prepare('SELECT id,evidence_data FROM evidence_records ORDER BY step_index').all();assert.equal(evidence.length,2);
    assert.deepEqual(evidence.map(row=>JSON.parse(row.evidence_data).source_verification.phase),['baseline','verification']);
    assert.ok(evidence.every(row=>JSON.parse(row.evidence_data).source_verification.finding_ids[0]===finding.id));
    const comparison=JSON.parse(evidence[1].evidence_data).source_comparison;
    assert.equal(comparison.status,'matched');assert.equal(comparison.baseline_evidence_id,evidence[0].id);
    assert.equal(comparison.runtime_verified,false);assert.equal(comparison.review_required,true);
    const versions=JSON.parse(evidence[1].evidence_data).source_verification.source_versions;
    assert.equal(versions[0].source_sha256,JSON.parse(finding.result_data).source_sha256);
    assert.equal(versions[0].snapshot_id,coverage.snapshot_id);
    const review=await request('/scans/'+task.scan_task_id+'/source-verifications',undefined,'alice','GET');
    assert.equal(review.runs[0].run_id,run.run_id);assert.equal(review.runs[0].evidence.length,2);
  });
}
