import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,mkdir,symlink,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import http from 'node:http';
import net from 'node:net';
import Database from 'better-sqlite3';
import {sourceTarget,loadSourceConnections,resolveSourceConnection,resolveSourceConnectionForTarget,publicSourceConnection} from '../src/services/sourceScanConnections.js';
import {collectSource,createSourceSnapshot} from '../src/services/sourceSnapshot.js';
import {createSourceContextIndex,relatedSourceContext} from '../src/services/sourceContext.js';
import {buildProgramContext} from '../src/services/programAgent.js';
import {normalizeSourceFinding} from '../src/services/sourceScanFindings.js';
import {runTargetRequest,parseTargetRequest} from '../src/tools/targetRequest.js';
import {auditSources,auditLegacySnapshot,recoverCscanAudits} from '../src/services/sourceAudit.js';
import {cscanFixture} from './helpers/cscanFixture.js';
import {parseCscanMarkdown} from '../src/services/cscanReport.js';
import {generateSourceVerification,recordSourceVerification} from '../src/services/sourceVerification.js';
import {parseResults} from '../src/services/scanExecutor.js';
import {runTool} from '../src/tools/toolRunner.js';
import {getDb,closeDb} from '../src/db/connection.js';
import {executeRun} from '../src/services/executionEngine.js';
import {runPreflightChecks} from '../src/services/preflightGate.js';

const root=fileURLToPath(new URL('../../',import.meta.url));
async function temp(t) {
  const path=await mkdtemp(join(tmpdir(),'rt-source-test-'));
  t.after(()=>rm(path,{recursive:true,force:true}));
  return path;
}
async function listen(t,server) {
  server.listen(0,'127.0.0.1');
  await new Promise(r=>server.once('listening',r));
  t.after(()=>new Promise(r=>server.close(r)));
  return server.address().port;
}
async function schema(db) {
  const dir=join(root,'backend/src/db/migrations');
  for(const name of (await readdir(dir)).sort()) {
    if(name.includes('import')) continue; // No private configuration or imported content in tests.
    const migration=await import(join(dir,name));
    (migration.default || migration.up)(db);
  }
  db.prepare("DELETE FROM system_config WHERE category='llm'").run();
}
function auditDb(t) {
  const db=new Database(':memory:');
  db.exec("CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT); CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT);");
  t.after(()=>db.close()); return db;
}
const cscanReport=(source,findings=[])=>({snapshot_id:source.snapshot_id,flow_id:'12',findings,
  coverage:{reviewed_files:source.documents.map(doc=>doc.path),omitted_files:[],complete:true}});
const args=spec=>[JSON.stringify(spec)];

test('legacy HTTP snapshot remains compatible without being the new project input',async t=>{
  const db=auditDb(t),hits=[];
  const server=http.createServer((req,res)=>{
    hits.push(req.url);
    if(req.url==='/selected/') res.end('<a href="main.c">main.c</a><a href="../unselected/">outside</a>');
    else if(req.url==='/selected/main.c') res.end('int main(void) { return 0; }\n');
    else {res.writeHead(404);res.end();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  const target='http://127.0.0.1:'+server.address().port+'/';
  const service=await cscanFixture(t,async({inventory,key,sources})=>{
    assert.deepEqual(inventory.map(f=>f.path),['main.c']);
    assert.equal(await readFile(join(sources,key,'main.c'),'utf8'),'int main(void) { return 0; }\n');
    return [];
  });
  const snapshotRoot=await temp(t);
  const result=await auditLegacySnapshot({scan_task_id:'directory-cscan',target:target+'selected/'},{db,
    parameters:{input_kind:'source',source_url:target+'selected/'},
    snapshot:(connection,options)=>createSourceSnapshot(connection,{...options,snapshotRoot}),
    runTool:()=>assert.fail('a source-folder task must not invoke network scanning')});
  assert.ok(result.outcomes.every(item=>item.success),JSON.stringify(result.outcomes));
  assert.deepEqual(hits,['/selected/','/selected/main.c']);
  assert.equal(service.counts.created,1);assert.equal(service.counts.finished,1);
  const rows=db.prepare('SELECT result_type,result_data FROM scan_results').all();
  assert.ok(rows.some(row=>row.result_type==='raw_output'));
  const coverage=JSON.parse(rows.find(row=>row.result_type==='source_coverage').result_data);
  assert.equal(coverage.cscan_complete,true);
  assert.equal(coverage.cscan.task_progress.finished,1);
  assert.equal(coverage.cscan.subtask_progress.finished,1);
});

test('selected SSH folder submits only its location, never collects or uploads files',async t=>{
  const db=auditDb(t),root=await temp(t),connections=join(root,'connections.json');
  await writeFile(connections,JSON.stringify([{id:'project',kind:'ssh',source_root:'/opt/project',host:'192.0.2.40',port:22,username:'reader',identity_file:'/private/key',targets:['http://example.test/']}]));
  const old=process.env.SOURCE_SCAN_CONNECTIONS_FILE;process.env.SOURCE_SCAN_CONNECTIONS_FILE=connections;
  t.after(()=>{if(old===undefined) delete process.env.SOURCE_SCAN_CONNECTIONS_FILE;else process.env.SOURCE_SCAN_CONNECTIONS_FILE=old;});
  let calls=0;
  const result=await auditSources({scan_task_id:'selected',target:'http://example.test/'},{db,
    parameters:{input_kind:'remote_directory',connection_id:'project',source_subdir:'module'},
    snapshot:()=>assert.fail('must not collect source'),cscan:()=>assert.fail('must not invoke snapshot scanner'),
    nativeScan:async (target,options)=>{calls++;assert.equal(target,'http://example.test/');
      assert.match(options.sourceLocation,/192\.0\.2\.40/);assert.match(options.sourceLocation,/\/opt\/project\/module/);
      assert.ok(!JSON.stringify(options).includes('/private/key'));
      return {flow_id:'20',markdown:'Source-Access: unavailable\nMissing access.',findings:[],source_access_reported:'unavailable'};}});
  assert.equal(calls,1);assert.equal(result.outcomes[0].success,false);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.input_mode,'remote_agent');assert.equal(coverage.cscan.state,'source_unavailable');
  assert.equal(coverage.transfer,undefined);
});

test('selected HTTP directory is passed to CScan without downloading its contents',async t=>{
  const db=auditDb(t);
  const result=await auditSources({scan_task_id:'http-direct',target:'http://example.test/'},{db,
    parameters:{input_kind:'remote_directory',source_url:'/project/'},
    snapshot:()=>assert.fail('must not download source'),
    nativeScan:async target=>{assert.equal(target,'http://example.test/project/');
      return {flow_id:'21',markdown:'Source-Access: available\nNo findings.',findings:[],source_access_reported:'available'};}});
  assert.ok(result.outcomes.every(item=>item.success));
});

test('source projects bind exact deployment endpoints and do not expose credential paths',async t=>{
  const path=await temp(t), config=join(path,'connections.json');
  await writeFile(config,JSON.stringify([{id:'c113',source_root:'/opt/lab/source',host:'192.168.1.113',username:'reader',identity_file:'/home/test/.ssh/lab',targets:['http://192.168.1.113:8090','tcp://192.168.1.113:8091']}]));
  const items=await loadSourceConnections(config);
  assert.equal((await resolveSourceConnection('c113','http://192.168.1.113:8090/',items)).id,'c113');
  await assert.rejects(resolveSourceConnection('c113','http://192.168.1.113:8089',items),/未绑定/);
  assert.equal(publicSourceConnection(items[0]).identity_file,undefined);
  for(const target of ['http://u:p@host','tcp://host','tcp://host:8091/abc','file:///src','../project']) assert.throws(()=>sourceTarget(target));
  assert.throws(()=>parseTargetRequest(args({url:'http://192.168.1.113:18090'}),'http://192.168.1.113:8090'),/范围/);
  assert.throws(()=>parseTargetRequest(args({url:'tcp://host:8091',exchanges:[{send:'x'.repeat(9000)}]})),/8 KB/);
});

test('runtime address automatically selects the one matching source project', async () => {
  const connections=[
    {id:'a',targets:['http://192.0.2.10:8080/']},
    {id:'b',targets:['tcp://192.0.2.10:8091']}
  ];
  assert.equal((await resolveSourceConnectionForTarget('http://192.0.2.10:8080',connections)).id,'a');
  assert.equal(await resolveSourceConnectionForTarget('http://192.0.2.10:8081',connections),null);
  await assert.rejects(resolveSourceConnectionForTarget('http://192.0.2.10:8080',connections.concat({id:'c',targets:['http://192.0.2.10:8080/']})),/多个源码项目/);
});

test('HTTP source directory follows same-origin index and freezes C/C++ files',async t=>{
  const pages={
    '/source/':'<a href="main.c">main.c</a><a href="sub/">sub/</a><a href="../outside.c">outside</a><a href="/source2/outside.c">outside</a><a href="large.c">large</a><a href="invalid.c">invalid</a>',
    '/source/sub/':'<a href="helper.h">helper.h</a>',
    '/source/main.c':'int main(){return 0;}',
    '/source/sub/helper.h':'#define OK 1',
    '/source/large.c':'x'.repeat(512*1024+1),
    '/source/invalid.c':Buffer.from([0xff])
  };
  const requested=[];
  const port=await listen(t,http.createServer((req,res)=>{
    requested.push(req.url);
    if(!(req.url in pages)){res.writeHead(404);return res.end();}
    res.setHeader('content-type',req.url.endsWith('/')?'text/html':'text/plain');res.end(pages[req.url]);
  }));
  const connection={id:'web',kind:'http',source_url:`http://127.0.0.1:${port}/source/`,targets:[`http://127.0.0.1:${port}/`],architecture:'arm64'};
  const snapshot=await createSourceSnapshot(connection,{snapshotRoot:await temp(t)});
  assert.deepEqual(snapshot.documents.map(file=>file.path).sort(),['main.c','sub/helper.h']);
  assert.equal(snapshot.skipped.length,2);
  assert.ok(!requested.includes('/outside.c') && !requested.includes('/source2/outside.c'));
});

test('collector reads actual UTF-8 sources, excludes symlinks and bounds files; snapshot freezes evidence',async t=>{
  const path=await temp(t), source=join(path,'source');
  await mkdir(source); await mkdir(join(source,'build'));
  await writeFile(join(source,'main.c'),'int main() {\n return 0;\n}\n');
  await writeFile(join(source,'build','ignored.c'),'ignored');
  await writeFile(join(path,'outside.c'),'secret');
  await symlink(join(path,'outside.c'),join(source,'escape.c'));
  await writeFile(join(source,'large.c'),'a'.repeat(512*1024+1));
  const connection={id:'local',kind:'local',source_root:source,architecture:'arm64'};
  const snapshot=await createSourceSnapshot(connection,{snapshotRoot:join(path,'snapshots')});
  assert.deepEqual(snapshot.files.map(f=>f.path),['main.c']);
  assert.equal(snapshot.skipped.length,2);
  await writeFile(join(source,'main.c'),'changed');
  assert.match(await readFile(join(snapshot.sourceDir,'main.c'),'utf8'),/return 0/);
  const finding=normalizeSourceFinding({file:'main.c',start_line:2,title:'finding',reason:'reason'},snapshot.documents);
  assert.equal(finding.code,' return 0;');
  assert.equal(finding.runtime_verified,false);
  assert.throws(()=>normalizeSourceFinding({file:'else.c',start_line:2,title:'x',reason:'y'},snapshot.documents),/未读取/);
  assert.throws(()=>normalizeSourceFinding({file:'main.c',start_line:50,title:'x',reason:'y'},snapshot.documents),/未读取/);
  await assert.rejects(collectSource(connection,{execute:async()=>({stdout:JSON.stringify({files:[{path:'../outside.c',content:'x'}],skipped:[]})})}),/无效路径/);
});

test('task-supplied HTTP directory is read by the audit without a configured source project',async t=>{
  const port=await listen(t,http.createServer((req,res)=>{
    if(req.url==='/custom/') return res.end('<a href="main.c">main.c</a>');
    if(req.url==='/custom/main.c') return res.end('int main(){return 0;}');
    res.writeHead(404);res.end();
  }));
  const db=auditDb(t), snapshotRoot=await temp(t), target=`http://127.0.0.1:${port}/app/`;
  const result=await auditLegacySnapshot({scan_task_id:'custom',target},{db,
    parameters:{source_url:'/custom/',ai_analysis:false},cscan:async source=>cscanReport(source),
    runTool:async()=>({success:true,stdout:'{}',stderr:''}),parseResults:()=>[],
    snapshot:(connection,options)=>createSourceSnapshot(connection,{...options,snapshotRoot})});
  assert.equal(result.outcomes.find(o=>o.tool_id==='source-reader').success,true);
  const row=db.prepare('SELECT manifest FROM source_audits').get();
  assert.equal(JSON.parse(row.manifest).source_url,`http://127.0.0.1:${port}/custom/`);
  const coverage=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='source_coverage'").get().result_data);
  assert.equal(coverage.source_read,true);assert.equal(coverage.files,1);
});

test('SSH collector uses a fixed read-only program and strict host verification',async ()=>{
  let invocation;
  await collectSource({kind:'ssh',source_root:"/opt/source with ' spaces",port:22,host:'192.168.1.113',username:'reader',identity_file:'/keys/read-only',known_hosts_file:'/keys/known_hosts'},{
    execute:async(bin,argv)=>{invocation={bin,argv};return {stdout:JSON.stringify({files:[{path:'a.c',content:'int x;'}],skipped:[]})};}
  });
  assert.equal(invocation.bin,'ssh');
  assert.ok(invocation.argv.includes('StrictHostKeyChecking=yes'));
  assert.ok(invocation.argv.includes('BatchMode=yes'));
  assert.ok(!invocation.argv.at(-1).includes('/opt/source'));
});

test('HTTP transport preserves response evidence without following redirects',async t=>{
  let visits=0;
  const port=await listen(t,http.createServer((req,res)=>{
    visits++;
    if(req.url==='/redirect') {res.writeHead(302,{Location:'/other'});res.end('redirect');}
    else {let body='';req.on('data',x=>body+=x);req.on('end',()=>res.end('reply:'+body));}
  }));
  const url='http://127.0.0.1:'+port;
  const redirect=await runTargetRequest(args({url:url+'/redirect'}));
  assert.equal(JSON.parse(redirect.stdout).status_code,302); assert.equal(visits,1);
  const result=await runTargetRequest(args({url,method:'POST',body:'hello'}),{target:url});
  assert.equal(result.success,true); assert.equal(JSON.parse(result.stdout).response,'reply:hello');
  assert.equal(JSON.parse(result.stdout).verification_status,'needs_review');
});

test('TCP transport exchanges menu input and detects premature close',async t=>{
  const port=await listen(t,net.createServer(socket=>{
    socket.write('menu>'); socket.on('data',data=>socket.end('echo:'+data));
  }));
  const result=await runTargetRequest(args({url:'tcp://127.0.0.1:'+port,exchanges:[{send:'1\n',wait_ms:0}]}));
  assert.equal(result.success,true); assert.match(JSON.parse(result.stdout).response,/menu>echo:1/);
  const incomplete=await runTargetRequest(args({url:'tcp://127.0.0.1:'+port,exchanges:[{send:'1\n',wait_ms:0},{send:'2\n',wait_ms:1000}]}));
  assert.equal(incomplete.success,false);assert.match(incomplete.error,/未完成/);
});

test('transport cancels, times out and caps responses while preserving partial evidence',async t=>{
  const port=await listen(t,http.createServer((req,res)=>{
    if(req.url==='/large') res.end('x'.repeat(100000));
    else {res.writeHead(200);res.write('waiting');}
  }));
  const url='http://127.0.0.1:'+port;
  const large=await runTargetRequest(args({url:url+'/large'}));
  assert.equal(large.outputLimitExceeded,true); assert.equal(JSON.parse(large.stdout).response.length,65536);
  const timeout=await runTargetRequest(args({url,timeout_ms:500}));
  assert.equal(timeout.timedOut,true);assert.match(JSON.parse(timeout.stdout).response,/waiting/);
  const controller=new AbortController();
  const pending=runTargetRequest(args({url}),{signal:controller.signal});setTimeout(()=>controller.abort(),25);
  assert.equal((await pending).aborted,true);
});

test('remote-only audits never claim source coverage, and source failures retain the network result',async t=>{
  const db=auditDb(t);
  const run=async()=>({success:true,stdout:'{"connected":true,"response":"hello"}'});
  await auditLegacySnapshot({scan_task_id:'remote',target:'tcp://127.0.0.1:8091'},{db,parameters:{},runTool:run,parseResults});
  const coverage=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='source_coverage'").get().result_data);
  assert.equal(coverage.source_read,false);assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
  const result=await auditLegacySnapshot({scan_task_id:'missing',target:'tcp://127.0.0.1:8091'},{db,parameters:{connection_id:'missing'},runTool:run,parseResults});
  assert.equal(result.outcomes[0].success,true);assert.equal(result.outcomes[1].success,false);
  const failedCoverage=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id='missing' AND result_type='source_coverage'").get().result_data);
  assert.equal(failedCoverage.source_read,false);assert.equal(failedCoverage.ai_complete,false);
  assert.equal(failedCoverage.source_errors.length,1);
});

test('CScan exceptions preserve the frozen snapshot and explicit incomplete coverage without local fallback',async t=>{
  const db=auditDb(t),document={path:'main.c',content:'int main(){return 0;}',start_line:1,end_line:1,sha256:'fixture'};
  const calls=[];
  const result=await auditLegacySnapshot({scan_task_id:'exceptions',target:'http://127.0.0.1:8090/'},{db,
    parameters:{source_url:'/code/'},
    snapshot:async()=>({snapshot_id:'frozen',connection_id:'p',files:[{path:'main.c'}],skipped:[],documents:[document],sourceDir:'/fixture'}),
    runTool:async tool=>{calls.push(tool);return {success:true,stdout:'{}'};},
    cscan:async(source,{onProgress})=>{onProgress({flow_id:'8',state:'running'});throw new Error('CScan API 请求超时');},
    llm:()=>assert.fail('local source model must not run')});
  assert.deepEqual(calls,['target-request']);
  assert.equal(result.outcomes.find(o=>o.tool_id==='cscan').success,false);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.snapshot_id,'frozen');assert.equal(coverage.cscan_complete,false);
  assert.equal(coverage.cscan.flow_id,'8');assert.deepEqual(coverage.source_errors,['CScan API 请求超时']);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_coverage'").get().n,1);
});

test('CScan accepts cited findings but rejects invented locations and marks coverage incomplete',async t=>{
  const db=auditDb(t),document={path:'a.c',content:'void f(char *s) {\n char b[8]; strcpy(b,s);\n}',start_line:1,end_line:3,sha256:'hash'};
  let calls=0;
  const result=await auditLegacySnapshot({scan_task_id:'audit',target:'http://127.0.0.1:8090/'},{db,
    parameters:{source_url:'/code/'},
    snapshot:async()=>({snapshot_id:'version',connection_id:'p',files:[{path:'a.c'}],skipped:[],documents:[document],sourceDir:'/fixture'}),
    runTool:async()=>({success:true,stdout:'{}'}),
    cscan:async source=>{calls++;return cscanReport(source,[
      {file:'a.c',start_line:2,title:'unchecked copy',reason:'no length check',cwe:'CWE-120'},
      {file:'imaginary.c',start_line:1,title:'fake',reason:'fake'}]);}});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,1);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(calls,1);assert.equal(coverage.rejected_findings.length,1);assert.equal(coverage.cscan_complete,false);
  assert.match(coverage.rejected_findings[0].reason,/未读取/);assert.ok(result.outcomes.some(o=>!o.success));
});

test('concurrent or repeated source audits never duplicate a remote CScan submission',async t=>{
  const db=auditDb(t),document={path:'main.c',content:'int fixture;',start_line:1,end_line:1,sha256:'fixture'};
  const task={scan_task_id:'duplicate',target:'http://127.0.0.1:8090/'};let calls=0;
  const context={db,parameters:{source_url:'/code/',input_kind:'source'},
    snapshot:async()=>({snapshot_id:'frozen',connection_id:'fixture',files:[{path:'main.c'}],skipped:[],documents:[document],sourceDir:'/fixture'}),
    runTool:()=>assert.fail('no local tool for a source-only scan'),
    cscan:async source=>{calls++;await new Promise(resolve=>setTimeout(resolve,10));return cscanReport(source);}};
  await Promise.all([auditLegacySnapshot(task,context),auditLegacySnapshot(task,context)]);
  assert.equal(calls,1);
  await assert.rejects(auditLegacySnapshot(task,context),/避免重复提交/);assert.equal(calls,1);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.cscan_complete,true);assert.equal(coverage.whole_project_complete,false);
});

test('generated TCP verification executes through the real engine and links manual review to evidence',async t=>{
  const db=getDb(':memory:');t.after(closeDb);await schema(db);
  const port=await listen(t,net.createServer(socket=>{socket.write('menu>');socket.on('data',x=>socket.end('ack:'+x));}));
  const target='tcp://127.0.0.1:'+port;
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status) VALUES ('s',?,'source_scan','COMPLETED')").run(target);
  const result=db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('s','source_finding',?)").run(JSON.stringify({file:'a.c',start_line:2,code:'strcpy(b,s);',title:'unchecked copy',runtime_verified:false}));
  const id=Number(result.lastInsertRowid),task={scan_task_id:'s',target,status:'COMPLETED'};
  const plan={name:'diagnostic',description:'bounded test; no exploit assertion',steps:[{name:'normal input',tool_id:'target-request',args_template:args({url:'<target>',exchanges:[{send:'1\n',wait_ms:0}]}),description:'observed menu',finding_ids:[id],expected_evidence:'menu response; memory corruption remains unverified'}]};
  const generated=await generateSourceVerification(db,task,[id],{llm:async()=>({ok:true,content:JSON.stringify(plan)})});
  assert.equal(generated.ok,true,generated.error);
  const badPlan=structuredClone(plan);badPlan.steps[0].args_template=args({url:'tcp://127.0.0.1:1'});
  assert.equal((await generateSourceVerification(db,task,[id],{llm:async()=>({ok:true,content:JSON.stringify(badPlan)})})).ok,false);
  const blocked=await runPreflightChecks({db,playbookId:generated.playbook_id,target:'tcp://127.0.0.1:1'});
  assert.equal(blocked.passed,false);
  db.prepare("INSERT INTO execution_runs(run_id,playbook_id,target,scan_task_id,status,engine_type) VALUES ('run',?,?,'s','PENDING','react')").run(generated.playbook_id,target);
  const executed=await executeRun('run');
  assert.equal(executed.ok,true,JSON.stringify(executed));
  const run=db.prepare("SELECT * FROM execution_runs WHERE run_id='run'").get();
  assert.equal(run.status,'COMPLETED',run.final_summary);assert.equal(run.engine_type,'mechanical');
  const evidence=db.prepare("SELECT * FROM evidence_records WHERE run_id='run'").all();
  assert.ok(evidence.length);assert.match(evidence[0].raw_stdout,/ack/);
  assert.throws(()=>recordSourceVerification(db,id,{run_id:'run',status:'supported',note:'result',evidence_ids:[999999]},'reviewer'),/不属于/);
  const review=recordSourceVerification(db,id,{run_id:'run',status:'inconclusive',note:'Normal input responded; no evidence of memory corruption.',evidence_ids:[evidence[0].id]},'reviewer');
  assert.equal(review.status,'inconclusive');
  assert.equal(JSON.parse(db.prepare('SELECT result_data FROM scan_results WHERE id=?').get(id).result_data).runtime_verified,false);
});

test('actual SAST tools inspect a frozen demo snapshot', {skip:process.env.SOURCE_TEST_SAST!=='1'}, async t=>{
  const path=await temp(t);
  const snapshot=await createSourceSnapshot({id:'demo',kind:'local',source_root:resolve(root,'data/source-targets/exploit-demo'),architecture:'arm64'},{snapshotRoot:path});
  let findings=0;
  for(const tool of ['cppcheck','flawfinder']) {
    const argv=tool==='cppcheck'?['-q','--enable=warning,portability,performance','--xml','--xml-version=2','/src/project']:['--csv','--minlevel=1','/src/project'];
    const result=await runTool(tool,argv,{sourceDir:snapshot.sourceDir,timeout:60000});
    assert.equal(result.success,true,result.stderr);
    const rows=parseResults('source_scan_'+tool,result.stdout+'\n'+result.stderr).filter(r=>r.result_type==='source_vuln');
    findings+=rows.length;
    assert.ok(rows.every(r=>r.result_data.file.startsWith('/src/project/')));
  }
  assert.ok(findings>0);
});

test('CScan preserves validated cross-file citations for downstream verification',async t=>{
  const db=auditDb(t),path=await temp(t),config=join(path,'config.json');
  const previous=process.env.SOURCE_SCAN_CONNECTIONS_FILE;
  process.env.SOURCE_SCAN_CONNECTIONS_FILE=config;
  t.after(()=>{if(previous===undefined) delete process.env.SOURCE_SCAN_CONNECTIONS_FILE;else process.env.SOURCE_SCAN_CONNECTIONS_FILE=previous;});
  await writeFile(config,JSON.stringify([{id:'p',kind:'local',source_root:path,targets:['http://127.0.0.1:8090']}]));
  const documents=[
    {path:'copy.c',content:'void copy(char *input) {\n char b[8]; strcpy(b,input);\n}',start_line:1,end_line:3,sha256:'copyhash'},
    {path:'entry.c',content:'int handle(char *request) {\n copy(request);\n return 0;\n}',start_line:1,end_line:4,sha256:'entryhash'},
    {path:'unrelated.c',content:'int unrelated = 0;',start_line:1,end_line:1,sha256:'otherhash'}
  ];
  const context=relatedSourceContext(documents[0],createSourceContextIndex(documents));
  assert.ok(context.some(d=>d.path==='entry.c'));
  assert.ok(!context.some(d=>d.path==='unrelated.c'));
  const finding={file:'copy.c',start_line:2,end_line:2,title:'unchecked external input',reason:'The caller passes request into a fixed buffer copy.',
    cwe:'CWE-120',severity:'high',preconditions:'Need runtime route and input length evidence',
    trace:[{file:'entry.c',start_line:2,end_line:2,role:'source',note:'Caller passes request; trust boundary still needs review'},
      {file:'copy.c',start_line:2,end_line:2,role:'sink',note:'Copy has no length argument'}]};
  assert.throws(()=>normalizeSourceFinding({...finding,trace:[{...finding.trace[0],start_line:99,end_line:99}]},documents),/未读取/);
  assert.throws(()=>normalizeSourceFinding({...finding,trace:[{...finding.trace[0],role:'confirmed'}]},documents),/角色/);
  await auditLegacySnapshot({scan_task_id:'trace',target:'http://127.0.0.1:8090'},{
    db,parameters:{connection_id:'p'},
    snapshot:async()=>({snapshot_id:'frozen',connection_id:'p',files:documents.map(d=>({path:d.path})),skipped:[],documents,sourceDir:path}),
    runTool:async tool=>{assert.equal(tool,'target-request');return {success:true,stdout:'{"connected":true}'};},
    cscan:async source=>cscanReport(source,[finding,{...finding,file:'../outside.c'},
      {...finding,trace:[{...finding.trace[0],file:'invented.c'}]}])
  });
  const rows=db.prepare("SELECT * FROM scan_results WHERE result_type='source_finding'").all();
  assert.equal(rows.length,1);
  const saved=JSON.parse(rows[0].result_data);
  assert.deepEqual(saved.tools,['cscan']);assert.equal(saved.analyses.length,1);
  assert.equal(saved.reason,finding.reason);assert.equal(saved.trace[0].code,' copy(request);');
  assert.equal(saved.trace[0].source_sha256,'entryhash');assert.equal(saved.runtime_verified,false);
  const planContext=buildProgramContext(rows);
  assert.equal(planContext[0].data.trace[0].file,'entry.c');assert.equal(planContext[0].data.analyses.length,1);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.rejected_findings.length,2);assert.equal(coverage.cscan_complete,false);
});

test('related source retrieval remains bounded for widespread symbols and large bodies',()=>{
  const documents=Array.from({length:100},(_,i)=>({path:i+'.c',start_line:1,end_line:100,sha256:String(i),
    content:Array.from({length:100},()=> 'char *p; copy(p); /* '+ 'x'.repeat(150)+' */').join('\n')}));
  const context=relatedSourceContext(documents[0],createSourceContextIndex(documents));
  assert.ok(context.length<=4);
  assert.ok(context.reduce((n,d)=>n+d.content.length,0)<=16000);
});

test('CScan cancellation retains Flow identity and coverage without importing late findings',async t=>{
  const db=auditDb(t),controller=new AbortController();
  const document={path:'main.c',content:'int x;',start_line:1,end_line:1,sha256:'fixture'};
  await assert.rejects(auditLegacySnapshot({scan_task_id:'cancel',target:'http://127.0.0.1:9/code/'},{db,
    parameters:{source_url:'/code/',input_kind:'source'},signal:controller.signal,
    snapshot:async()=>({snapshot_id:'v1',connection_id:'p',documents:[document],files:[{path:'main.c'}],skipped:[]}),
    cscan:async(source,{onProgress})=>{onProgress({flow_id:'41',state:'running'});controller.abort();return cscanReport(source);}}),/取消/);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.cscan.flow_id,'41');assert.equal(coverage.cscan.state,'cancelled');
  assert.equal(coverage.cscan_complete,false);
  assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
});

test('startup reconciles orphaned CScan flows, preserves unknown submissions and leaves legacy audits intact',async t=>{
  const db=auditDb(t);
  db.exec('CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,status TEXT,completed_at TEXT,error_message TEXT)');
  for(const [id,cscan] of [['known',{flow_id:'7',state:'running'}],['unknown',{state:'submitting',submission_uncertain:true}],
    ['unreachable',{flow_id:'8',state:'cancelled',stop_status:'unconfirmed'}],['legacy',null]]) {
    const coverage=cscan?{engine:'cscan',cscan,source_errors:[]}:{files:1,ai_complete:true};
    db.prepare('INSERT INTO source_audits VALUES (?,?,?,\'{}\',?,\'fixture\')').run(id,'v1','p',JSON.stringify(coverage));
    db.prepare("INSERT INTO scan_tasks(scan_task_id,status) VALUES (?,'RUNNING')").run(id);
    db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'source_coverage',?)").run(id,JSON.stringify(coverage));
  }
  const stopped=[];
  const recovered=await recoverCscanAudits(db,{connect:async()=>({stop:async id=>{stopped.push(id);if(id==='8') throw new Error('unreachable');}})});
  assert.equal(recovered,3);assert.deepEqual(stopped.sort(),['7','8']);
  const read=id=>JSON.parse(db.prepare('SELECT analysis FROM source_audits WHERE scan_task_id=?').get(id).analysis);
  assert.equal(read('known').cscan.stop_status,'acknowledged');assert.equal(read('unreachable').cscan.stop_status,'unconfirmed');
  assert.equal(read('unknown').cscan.submission_uncertain,true);assert.match(read('unknown').source_errors[0],/不确定/);
  assert.equal(db.prepare("SELECT status FROM scan_tasks WHERE scan_task_id='legacy'").get().status,'RUNNING');
  assert.equal(db.prepare("SELECT count(*) n FROM scan_tasks WHERE status='FAILED'").get().n,3);
  assert.equal(read('legacy').ai_complete,true);
});

test('native Markdown findings enter verification context but never claim complete source coverage',async t=>{
  const db=auditDb(t),document={path:'input.c',content:'void copy(char *s) {\n char b[8]; strcpy(b,s);\n}',
    start_line:1,end_line:3,sha256:'fixture'};
  const result=await auditLegacySnapshot({scan_task_id:'markdown',target:'http://127.0.0.1:9/code/'},{db,
    parameters:{source_url:'/code/',input_kind:'source'},
    snapshot:async()=>({snapshot_id:'v1',connection_id:'p',documents:[document],files:[{path:'input.c'}],skipped:[]}),
    cscan:async source=>({...parseCscanMarkdown('## Copy input\nFile: input.c\nLine: 2\nEvidence: No capacity check\nSeverity: high',source.snapshot_id),flow_id:'42'})});
  const finding=db.prepare("SELECT * FROM scan_results WHERE result_type='source_finding'").get();
  assert.equal(JSON.parse(finding.result_data).code,' char b[8]; strcpy(b,s);');
  assert.equal(JSON.parse(finding.result_data).runtime_verified,false);
  assert.equal(buildProgramContext([finding])[0].data.file,'input.c');
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.report_format,'markdown');assert.equal(coverage.cscan_complete,false);
  assert.equal(coverage.reviewed_files.length,0);assert.equal(result.outcomes.find(o=>o.tool_id==='coverage').success,false);
  const raw=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='raw_output'").get().result_data);
  assert.match(raw.report,/No capacity check/);
});

test('restart finishes completed Flow cleanup without failing completed scans and reconciles interrupted report imports',async t=>{
  const db=auditDb(t);
  db.exec('CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,status TEXT,completed_at TEXT,error_message TEXT)');
  for(const [id,status,remote] of [['finalize','PARTIAL',{state:'finished',flow_id:'51',finish_status:'unconfirmed'}],
    ['import','RUNNING',{state:'finished',flow_id:'52',flow_status:'finished',finish_status:'acknowledged'}]]) {
    const coverage={engine:'cscan',cscan:remote,cscan_complete:true,source_errors:[]};
    db.prepare('INSERT INTO source_audits VALUES (?,?,?,\'{}\',?,\'fixture\')').run(id,'v1','p',JSON.stringify(coverage));
    db.prepare('INSERT INTO scan_tasks(scan_task_id,status) VALUES (?,?)').run(id,status);
  }
  const finished=[];
  await recoverCscanAudits(db,{connect:async()=>({finish:async id=>finished.push(id),stop:()=>assert.fail('completed Flows must not be stopped')})});
  assert.deepEqual(finished,['51']);
  assert.equal(db.prepare("SELECT status FROM scan_tasks WHERE scan_task_id='finalize'").get().status,'PARTIAL');
  assert.equal(db.prepare("SELECT status FROM scan_tasks WHERE scan_task_id='import'").get().status,'FAILED');
  const coverage=JSON.parse(db.prepare("SELECT analysis FROM source_audits WHERE scan_task_id='import'").get().analysis);
  assert.equal(coverage.cscan.stop_status,'not_required');assert.equal(coverage.cscan_complete,false);
});
