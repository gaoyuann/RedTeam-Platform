import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import Database from 'better-sqlite3';
import {readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {scanCscanTarget,normalizeCscanReportedFinding} from '../src/services/cscanNative.js';
import {cscanConfig} from '../src/services/cscanClient.js';
import {cscanSourcePath,cscanTarget} from '../src/services/cscanTarget.js';
import {auditSources} from '../src/services/sourceAudit.js';
import {programExecutionTarget} from '../src/services/programScan.js';
import {executeScan} from '../src/services/scanExecutor.js';
import {normalizeTaskScope,isTargetInScope,scopeBlockReason} from '../src/services/taskScope.js';
import {getDb,closeDb} from '../src/db/connection.js';
import pipelineRoutes from '../src/routes/pipelines.js';
import scanRoutes from '../src/routes/scans.js';
import {pipelineScans} from '../src/services/scanResultQuery.js';
import {ensureVerification,verificationDetail} from '../src/services/findingVerification.js';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const report='## Unchecked copy\nFile: src/input.c\nLine: 12\nSeverity: high\nCWE: CWE-120\nEvidence: Copy into a fixed buffer without checking capacity\nPreconditions: Input control remains unknown\nRemediation: Enforce the buffer capacity';

test('remote CScan targets accept hosts, ports and remote paths without a /src mount requirement',()=>{
  assert.equal(cscanTarget('192.0.2.40'),'192.0.2.40');
  assert.equal(cscanTarget('192.0.2.40:8089'),'tcp://192.0.2.40:8089');
  assert.equal(cscanTarget('http://192.0.2.40:8089'),'http://192.0.2.40:8089/');
  assert.equal(cscanTarget('/var/www/project/'),'/var/www/project');
  for(const target of ['/','/opt/project/../private','file:///etc/passwd','http://user:secret@example.invalid/','192.0.2.0/24'])
    assert.throws(()=>cscanTarget(target));
  const scope=normalizeTaskScope({cscan_target:'/var/www/project'},'/var/www/project');
  assert.equal(isTargetInScope(scope,'/var/www/project/src/a.c'),true);
  assert.equal(isTargetInScope(scope,'/var/www/other'),false);
  assert.match(scopeBlockReason(scope,'/var/www/project','port_scan'),/不能用于网络扫描/);
  assert.equal(isTargetInScope(normalizeTaskScope({},'192.0.2.40:8089'),'tcp://192.0.2.40:8089'),true);
});
async function listen(t,server) {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  return 'http://127.0.0.1:'+server.address().port;
}
async function protocol(t,markdown=report) {
  const calls=[];
  const url=await listen(t,http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req) raw+=chunk;
    const body=JSON.parse(raw);calls.push(body);
    assert.equal(req.headers.authorization,'Bearer fixture-cscan');
    res.setHeader('content-type','application/json');
    const task={id:'1',flowId:'91',status:'finished',result:markdown,subtasks:[{id:'1',status:'finished',result:''}]};
    if(body.query.includes('createFlow')) res.end(JSON.stringify({data:{createFlow:{id:'91',status:'running'}}}));
    else if(body.query.includes('CScanReport')) res.end(JSON.stringify({data:{tasks:[task]}}));
    else if(body.query.includes('finishFlow')) res.end(JSON.stringify({data:{finishFlow:'success'}}));
    else if(body.query.includes('stopFlow')) res.end(JSON.stringify({data:{stopFlow:'success'}}));
    else res.end(JSON.stringify({data:{flow:{id:'91',status:'waiting'},tasks:[task]}}));
  }));
  const env={CSCAN_API_URL:url,CSCAN_API_TOKEN:'fixture-cscan',CSCAN_POLL_MS:'10',CSCAN_TIMEOUT_MS:'3000',
    CSCAN_SOURCES_DIR:'/does-not-exist/sources',CSCAN_WORK_DIR:'/does-not-exist/reports'};
  return {calls,env,config:cscanConfig(env)};
}

test('native source scan passes the service path and requirements, consumes tasks.result without collecting source or reading shared files',async t=>{
  const {calls,config}=await protocol(t);
  const result=await scanCscanTarget('/src/project',{notes:'重点检查输入长度',config,llm:()=>assert.fail('explicit report fields need no second model')});
  assert.equal(result.report_source,'task_result');assert.equal(result.flow_id,'91');assert.equal(result.findings.length,1);
  const input=calls[0].variables.input;
  assert.match(input,/\/src\/project/);assert.match(input,/重点检查输入长度/);assert.match(input,/没有上传文件/);
  assert.doesNotMatch(input,/findings\.json|snapshot_id|SHA256/);
  assert.ok(calls.some(c=>c.query.includes('CScanReport')));assert.ok(calls.at(-1).query.includes('finishFlow'));
});

test('remote target and audit requirements go to the Flow together with the exact scope',async t=>{
  const {calls,config}=await protocol(t,'Source-Access: available\n'+report);
  const scope=normalizeTaskScope({task_scope:{excludes:['http://192.0.2.40:8089/private/']}},'http://192.0.2.40:8089/');
  const result=await scanCscanTarget('http://192.0.2.40:8089/',{notes:'源码在靶机 /var/www/project，使用既有授权连接',scope,config});
  assert.equal(result.source_access_reported,'available');
  const input=calls[0].variables.input;
  assert.match(input,/http:\/\/192\.0\.2\.40:8089\//);assert.match(input,/靶机网络目标/);
  assert.match(input,/\/var\/www\/project/);assert.ok(input.includes(JSON.stringify(scope)));
  assert.doesNotMatch(input,/目标是 CScan 执行环境中的文件或目录路径|先确认该路径在执行容器中/);
  assert.equal(result.findings.length,1);
});

test('unavailable or unconfirmed source access preserves the report and cannot complete a source audit',async t=>{
  for(const access of ['unavailable','unknown']) await t.test(access,async t=>{
    const db=new Database(':memory:');t.after(()=>db.close());
    db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT)');
    const markdown=(access==='unavailable'?'Source-Access: unavailable\nSource-Reason: 靶机源码连接不可用\n':'')+report;
    const {config}=await protocol(t,markdown);
    const result=await auditSources({scan_task_id:'remote',target:'192.0.2.40'},{db,parameters:{cscan_target:'192.0.2.40',input_kind:'agent'},
      snapshot:()=>assert.fail('remote Flow must not use platform source collection'),runTool:()=>assert.fail('no local tool runs'),
      nativeScan:(target,options)=>scanCscanTarget(target,{...options,config})});
    assert.ok(result.outcomes.some(outcome=>!outcome.success));
    assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,access==='unavailable'?0:1,
      'unconfirmed access retains report-backed candidates without claiming completeness');
    assert.equal(JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='raw_output'").get().result_data).report,markdown);
    const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
    assert.equal(coverage.input_mode,'remote_agent');assert.equal(coverage.cscan_complete,false);
    assert.equal(coverage.source_access_reported,access);assert.equal(coverage.source_read,false);
  });
});

test('native report retains subtask evidence when the final task summary has no findings',async t=>{
  const calls=[];
  const url=await listen(t,http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req)raw+=chunk;const body=JSON.parse(raw);calls.push(body.query);
    res.setHeader('content-type','application/json');
    if(body.query.includes('createFlow'))return res.end(JSON.stringify({data:{createFlow:{id:'92',status:'running'}}}));
    if(body.query.includes('finishFlow'))return res.end(JSON.stringify({data:{finishFlow:'success'}}));
    const task={id:'1',flowId:'92',status:'finished',result:'Source audit completed.',subtasks:[{id:'1',status:'finished',result:report}]};
    res.end(JSON.stringify({data:{flow:{id:'92',status:'waiting'},tasks:[task]}}));
  }));
  const config=cscanConfig({CSCAN_API_URL:url,CSCAN_API_TOKEN:'fixture',CSCAN_POLL_MS:'10'});
  const result=await scanCscanTarget('/src/project',{config,llm:()=>assert.fail('subtask report already supplies explicit evidence')});
  assert.equal(result.findings.length,1);assert.match(result.markdown,/Source audit completed/);assert.match(result.markdown,/Unchecked copy/);
  assert.ok(calls.some(query=>query.includes('subtasks{id status result}')));
});

test('native report AI only structures returned evidence and rejects invented citations without claiming source verification',async t=>{
  const prose='The unchecked copy is located in src/input.c at line 12. Destination capacity is not checked.';
  const {config}=await protocol(t,prose);
  const result=await scanCscanTarget('/src/project',{config,llm:async messages=>{
    assert.equal(JSON.parse(messages[1].content).report,prose);
    return {ok:true,content:JSON.stringify({findings:[{file:'src/input.c',start_line:12,title:'Unchecked copy',reason:'Destination capacity is not checked.'}]})};
  }});
  const data=normalizeCscanReportedFinding(result.findings[0],result.markdown,'/src/project');
  assert.equal(data.source_location_verified,false);assert.equal(data.source_sha256,null);assert.equal(data.snapshot_id,null);
  assert.equal(data.runtime_verified,false);assert.equal(data.code,'');
  assert.throws(()=>normalizeCscanReportedFinding({...result.findings[0],reason:'invented evidence'},prose,'/src/project'),/未出现/);
  assert.throws(()=>normalizeCscanReportedFinding({...result.findings[0],file:'/etc/passwd'},prose,'/src/project'),/超出|源码路径/);
  assert.throws(()=>normalizeCscanReportedFinding({...result.findings[0],file:'/src/project/../private'},prose,'/src/project'),/源码路径/);
});

test('native parser failure retains the complete original service report and leaves scan partial without local source scanning',async t=>{
  const db=new Database(':memory:');t.after(()=>db.close());
  db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT)');
  const {config}=await protocol(t,'No structured fields were returned.');
  const result=await auditSources({scan_task_id:'native',target:'/src/project'},{db,parameters:{source_path:'/src/project',input_kind:'source'},
    snapshot:()=>assert.fail('native mode must not collect or snapshot source'),runTool:()=>assert.fail('native mode must not run platform tools'),
    nativeScan:(path,options)=>scanCscanTarget(path,{...options,config,llm:async()=>({ok:false,error:'offline'})})});
  assert.equal(result.outcomes.find(o=>o.tool_id==='report-parser').success,false);
  const raw=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='raw_output'").get().result_data);
  assert.equal(raw.report,'No structured fields were returned.');
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.input_mode,'service_path');assert.equal(coverage.whole_project_complete,false);
  assert.equal(coverage.source_read,false);assert.equal(coverage.cscan_complete,false);
  await assert.rejects(auditSources({scan_task_id:'native',target:'/src/project'},{db,parameters:{source_path:'/src/project'}}),/重复扫描/);
});

test('CScan service path scope is explicit, never becomes a network target, and traversal is rejected',()=>{
  const config={source_path:'/src/project',input_kind:'source'};
  const scope=normalizeTaskScope(config,'/src/project');
  assert.equal(isTargetInScope(scope,'/src/project/sub/file.c'),true);assert.equal(isTargetInScope(scope,'/src/project-other'),false);
  assert.equal(isTargetInScope(scope,'http://example.com/'),false);
  assert.match(scopeBlockReason(scope,'/src/project','port_scan'),/不能用于网络扫描/);
  assert.equal(scopeBlockReason(scope,'/src/project','source_scan'),null);
  const excluded=normalizeTaskScope({...config,task_scope:{excludes:['/src/project/private']}},'/src/project');
  assert.match(scopeBlockReason(excluded,'/src/project','source_scan'),/排除路径/);
  assert.equal(programExecutionTarget({target:'/src/project',parameters:config}),null);
  assert.equal(programExecutionTarget({target:'http://example.com/',parameters:{...config,runtime_target:'http://example.com/'}}),'http://example.com/');
  for(const path of ['/src/project/../other','/etc','/src','C:\\project','http://example.com/source/','/src/a\nignore'])
    assert.throws(()=>cscanSourcePath(path));
  assert.throws(()=>normalizeTaskScope({...config,task_scope:{includes:['http://example.com/']}},'http://example.com/'),/授权范围/);
});

test('default CScan environment check needs API credentials, not shared source or report directories',async t=>{
  const {env}=await protocol(t);
  const result=await promisify(execFile)(process.execPath,[fileURLToPath(new URL('../scripts/check-source-environment.js',import.meta.url))],
    {env:{...process.env,...env},timeout:5000});
  const data=JSON.parse(result.stdout);
  assert.equal(data.source_kind,'service');assert.equal(data.passed,true);
  assert.equal(data.checks.some(c=>['cscan_sources','cscan_reports','python','ssh','data/source-scan/snapshots'].includes(c.name)),false);
});

test('native report retrieval honors the overall scan deadline and retains Flow identity',async()=>{
  const config={...cscanConfig({}),timeoutMs:60,pollMs:10};let stopped=0;let reportSignal;
  const progress=[];
  await assert.rejects(scanCscanTarget('/src/project',{config,onProgress:p=>progress.push(p),client:{
    create:async()=>({id:'90',status:'waiting'}),
    flow:async()=>({id:'90',status:'waiting',tasks:[{status:'finished',subtasks:[]}]}),
    report:async(id,{signal})=>{reportSignal=signal;await new Promise((resolve,reject)=>{
      const fail=()=>reject(new Error('deadline'));signal.addEventListener('abort',fail,{once:true});if(signal.aborted)fail();
    });},stop:async()=>{stopped++;},
  }}),/超时/);
  assert.equal(reportSignal.aborted,true);assert.equal(stopped,1);
  assert.equal(progress.at(-1).flow_id,'90');assert.equal(progress.at(-1).state,'timed_out');
});

test('source task workbench sends one CScan Flow, no port scan; results enter F08 with missing runtime conditions',async t=>{
  const {env,calls}=await protocol(t);
  const old=Object.fromEntries(Object.keys(env).map(k=>[k,process.env[k]]));Object.assign(process.env,env);
  t.after(()=>{for(const [key,value] of Object.entries(old)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  const db=getDb(':memory:');t.after(closeDb);
  const directory=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for(const name of (await readdir(directory)).sort()) {if(name.includes('import')) continue;const m=await import(directory+name);(m.default || m.up)(db);}
  db.prepare("INSERT OR IGNORE INTO users(username,password,role) VALUES ('alice','fixture','user')").run();
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:'alice',role:'user'};next();});
  app.use('/pipelines',pipelineRoutes(db));app.use('/scans',scanRoutes(db));
  const base=await listen(t,http.createServer(app));
  const request=async(path,body,method='POST')=>{
    const response=await fetch(base+path,{method,headers:{'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
    return {status:response.status,body:await response.json()};
  };
  const created=await request('/pipelines',{target:'/src/project',config:{test_type:'program',input_kind:'source',source_path:'/src/project',
    authorization_confirmed:true,authorization_scope:'/src/project'}});
  assert.equal(created.status,201,JSON.stringify(created.body));
  const id=created.body.data.pipeline_id;assert.equal((await request('/pipelines/'+id+'/start',{})).status,202);
  const deadline=Date.now()+5000;
  while(Date.now()<deadline && db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status==='running')
    await new Promise(resolve=>setTimeout(resolve,20));
  const pipeline=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  assert.equal(pipeline.status,'awaiting_approval',pipeline.error_message);
  const scans=pipelineScans(db,pipeline);assert.equal(scans.length,1);assert.equal(scans[0].scan_type,'source_scan');
  assert.equal(calls.filter(c=>c.query.includes('createFlow')).length,1);
  const row=db.prepare("SELECT * FROM scan_results WHERE scan_task_id=? AND result_type='source_finding'").get(scans[0].scan_task_id);
  assert.ok(row);assert.equal(JSON.parse(row.result_data).evidence_origin,'cscan_report');
  const item=ensureVerification(db,pipeline,row.id),detail=verificationDetail(db,pipeline,item.id);
  assert.equal(detail.eligible,true);assert.equal(detail.default_target,null);assert.equal(detail.entry_context.source,'source_only');
  const scan=await request('/scans',{target:'/src/project',scan_type:'program_scan',parameters:{source_path:'/src/project',source_notes:'check input'}});
  assert.equal(scan.status,201);assert.equal(scan.body.data.scan_type,'source_scan');
  assert.equal(JSON.parse(scan.body.data.parameters).source_notes,'check input');
  const blocked=await request('/pipelines/'+id,{config:{source_path:'/src/other',input_kind:'source',scan_mode:'source_assisted'}},'PUT');
  assert.equal(blocked.status,400);
});

test('API accepts a target URL without a source path and executes the remote Flow; arbitrary remote paths also work in the task workbench',async t=>{
  const {env,calls}=await protocol(t,'Source-Access: available\n'+report);
  const old=Object.fromEntries(Object.keys(env).map(k=>[k,process.env[k]]));Object.assign(process.env,env);
  t.after(()=>{for(const [key,value] of Object.entries(old)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  const db=getDb(':memory:');t.after(closeDb);
  const directory=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for(const name of (await readdir(directory)).sort()) {if(name.includes('import')) continue;const m=await import(directory+name);(m.default || m.up)(db);}
  db.prepare("INSERT OR IGNORE INTO users(username,password,role) VALUES ('alice','fixture','user')").run();
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:'alice',role:'user'};next();});
  app.use('/pipelines',pipelineRoutes(db));app.use('/scans',scanRoutes(db));
  const base=await listen(t,http.createServer(app));
  const request=async(path,body,method='POST')=>{
    const response=await fetch(base+path,{method,headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    return {status:response.status,body:await response.json()};
  };
  const target='http://192.0.2.40:8089/';
  const created=await request('/pipelines',{target,config:{test_type:'program',input_kind:'agent',cscan_target:target,
    source_notes:'源码在靶机 /var/www/project',authorization_confirmed:true,authorization_scope:target}});
  assert.equal(created.status,201,JSON.stringify(created.body));
  const config=created.body.data.config;
  assert.equal(config.cscan_target,target);assert.equal(config.source_path,null);assert.equal(config.scan_mode,'source_assisted');
  assert.equal(programExecutionTarget({target,config}),target);
  const portTarget=await request('/pipelines',{target:'192.0.2.40:8089',config:{input_kind:'agent',
    task_scope:{includes:['192.0.2.40:8089']}}});
  assert.equal(portTarget.status,201,JSON.stringify(portTarget.body));
  assert.equal(portTarget.body.data.target,'tcp://192.0.2.40:8089');
  const blocked=await request('/pipelines',{target,config:{input_kind:'agent',cscan_target:'/var/www/project',task_scope:{includes:[target]}}});
  assert.equal(blocked.status,400,'a separate remote source target must also be authorized');
  const scan=await request('/scans',{target,scan_type:'program_scan',parameters:{input_kind:'agent',source_notes:'源码在靶机 /var/www/project'}});
  assert.equal(scan.status,201,JSON.stringify(scan.body));
  const scanId=scan.body.data.scan_task_id;
  assert.equal(scan.body.data.scan_type,'source_scan');
  assert.equal(JSON.parse(scan.body.data.parameters).cscan_target,target);
  const result=await executeScan(scanId);assert.equal(result.status,'COMPLETED',JSON.stringify(result));
  const findings=db.prepare("SELECT * FROM scan_results WHERE scan_task_id=? AND result_type='source_finding'").all(scanId);
  assert.equal(findings.length,1);assert.equal(JSON.parse(findings[0].result_data).source_location_verified,false);
  const count=calls.length;assert.equal((await executeScan(scanId)).ok,false);assert.equal(calls.length,count);
  const remotePath='/var/www/project';
  const pathTask=await request('/pipelines',{target:remotePath,config:{test_type:'program',input_kind:'agent',
    source_notes:'审阅该远端路径',authorization_confirmed:true,authorization_scope:remotePath}});
  assert.equal(pathTask.status,201,JSON.stringify(pathTask.body));
  const id=pathTask.body.data.pipeline_id;
  assert.equal((await request('/pipelines/'+id+'/start',{})).status,202);
  const deadline=Date.now()+5000;
  while(Date.now()<deadline && db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status==='running')
    await new Promise(resolve=>setTimeout(resolve,20));
  const pipeline=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  assert.equal(pipeline.status,'awaiting_approval',pipeline.error_message);
  const scans=pipelineScans(db,pipeline);assert.equal(scans.length,1);
  assert.equal(JSON.parse(scans[0].parameters).cscan_target,remotePath);
  const finding=db.prepare("SELECT * FROM scan_results WHERE scan_task_id=? AND result_type='source_finding'").get(scans[0].scan_task_id);
  assert.ok(finding);
  const item=ensureVerification(db,pipeline,finding.id),detail=verificationDetail(db,pipeline,item.id);
  assert.equal(detail.default_target,null);assert.equal(detail.entry_context.source,'source_only');
  const changed=await request('/pipelines/'+id,{config:{cscan_target:'/var/www/other',input_kind:'agent'}},'PUT');
  assert.equal(changed.status,400);
  assert.equal(calls.filter(call=>call.query.includes('createFlow')).length,2);
});
