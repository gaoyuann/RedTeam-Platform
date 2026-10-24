import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import Database from 'better-sqlite3';
import {readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {scanCscanTarget,normalizeCscanReportedFinding,parseNativeReport} from '../src/services/cscanNative.js';
import {findingVerificationEntry} from '../src/services/findingVerificationEntry.js';
import {cscanConfig} from '../src/services/cscanClient.js';
import {cscanSourcePath,cscanTarget} from '../src/services/cscanTarget.js';
import {auditSources,recoverCscanAudits} from '../src/services/sourceAudit.js';
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

function reportDb(t) {
  const db=new Database(':memory:');t.after(()=>db.close());
  db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT)');
  return db;
}

test('live scans translate legacy source locations to native CScan input without snapshot or mount work',async t=>{
  for(const parameters of [{source_url:'/source/',input_kind:'source'},{}]) {
    const db=reportDb(t),target='http://192.0.2.40:8089/source/';let calls=0;
    db.exec('CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,parameters TEXT)');
    db.prepare("INSERT INTO scan_tasks VALUES ('native-entry',?)").run(JSON.stringify(parameters));
    const result=await auditSources({scan_task_id:'native-entry',scan_type:'source_scan',target},{db,parameters,
      snapshot:()=>assert.fail('a live scan must never collect a snapshot'),
      cscan:()=>assert.fail('a live scan must never stage a snapshot'),
      runTool:()=>assert.fail('source retrieval belongs to CScan'),
      nativeScan:async(source,options)=>{
        calls++;assert.equal(source,target);
        assert.equal(isTargetInScope(options.scope,source),true);
        return {flow_id:'91',markdown:'Source-Access: available\n'+report,findings:[],source_access_reported:'available'};
      }});
    assert.equal(calls,1);assert.ok(result.outcomes.every(item=>item.success));
    const row=db.prepare('SELECT manifest,analysis FROM source_audits').get();
    assert.equal(JSON.parse(row.manifest).kind,'service_report');
    assert.equal(JSON.parse(row.analysis).input_mode,'remote_agent');
    const retainedParameters=db.prepare('SELECT parameters FROM scan_tasks').get().parameters;
    await assert.rejects(auditSources({scan_task_id:'native-entry',scan_type:'source_scan',target},{db,
      parameters:{source_url:'/other/',input_kind:'source'},nativeScan:()=>assert.fail('must not submit twice')}),/避免重复扫描/);
    assert.equal(db.prepare('SELECT parameters FROM scan_tasks').get().parameters,retainedParameters,'rejected retries cannot change the source or runtime entry');
  }
});

test('CScan retains raw subtask progress and only imports after every task finishes',async t=>{
  const db=reportDb(t);let polls=0,finished=false;
  const second=report.replace('Copy into a fixed buffer without checking capacity','Second path also copies without a bound');
  const client={
    create:async()=>({id:'91',status:'running'}),
    flow:async()=>{
      polls++;
      assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
      if(polls===2) {
        const raw=db.prepare("SELECT result_data FROM scan_results WHERE result_type='raw_output'").all();
        assert.ok(raw.some(row=>JSON.parse(row.result_data).report===report));
      }
      const subtasks=[{id:'sub1',status:'finished',result:report},
        {id:'sub2',status:polls<3?'running':'finished',result:polls<3?'':second}];
      return {id:'91',status:polls<3?'running':'waiting',tasks:[{id:'task1',flowId:'91',status:polls<3?'running':'finished',subtasks}]};
    },
    report:async()=>{assert.equal(polls,3);return 'Source-Access: available\n'+report+'\n\n'+second;},
    finish:async()=>{finished=true;return true;},stop:async()=>true,
  };
  const result=await auditSources({scan_task_id:'batch',target:'/src/project'},{db,parameters:{source_path:'/src/project'},
    nativeScan:(target,options)=>scanCscanTarget(target,{...options,client,config:{pollMs:1,timeoutMs:3000},
      onProgress:state=>{if(state.state==='parsing') assert.equal(finished,true);return options.onProgress(state);},
      llm:async messages=>JSON.parse(messages[1].content).report_phase==='progress'?{ok:false}:assert.fail('explicit final fields')})});
  assert.ok(result.outcomes.every(item=>item.success));
  const rows=db.prepare("SELECT * FROM scan_results WHERE result_type='source_finding'").all();
  assert.equal(rows.length,1);
  const finding=JSON.parse(rows[0].result_data);
  assert.deepEqual(finding.source_subtask_ids,['sub1','sub2']);
  assert.equal(finding.report_evidence.length,2);assert.equal(finding.runtime_verified,false);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.cscan.state,'finished');assert.equal(coverage.cscan.scan_complete,true);
  assert.equal(coverage.cscan.incremental,undefined);
});

test('final report parsing runs once despite progress failures; retained reports retry without rescanning or duplicate IDs',async t=>{
  const db=reportDb(t);let polls=0,calls=0,progressCalls=0,creates=0,finished=false;
  const raw='src/input.c line 12: Copy into a fixed buffer without checking capacity';
  const task={scan_task_id:'retry',target:'/src/project'},parameters={source_path:'/src/project'};
  const client={create:async()=>{creates++;return {id:'91',status:'running'};},flow:async()=>{
    polls++;assert.equal(calls,0);
    return {id:'91',status:polls<5?'running':'waiting',tasks:[{id:'t',flowId:'91',status:polls<5?'running':'finished',
      result:raw,subtasks:[{id:'s',status:'finished',result:raw}]}]};
  },report:async()=>raw,finish:async()=>{finished=true;return true;},stop:async()=>true};
  await auditSources(task,{db,parameters,nativeScan:(target,options)=>scanCscanTarget(target,{...options,client,config:{pollMs:1,timeoutMs:3000},
    llm:async messages=>{
      if(JSON.parse(messages[1].content).report_phase==='progress') {assert.equal(finished,false);progressCalls++;return {ok:false};}
      assert.equal(finished,true);calls++;return {ok:false};
    }})});
  assert.equal(calls,1);assert.equal(progressCalls,3,'the same failed progress report has at most three attempts');
  let coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.cscan.state,'report_error');assert.equal(coverage.cscan_complete,false);
  assert.ok(db.prepare("SELECT result_data FROM scan_results WHERE result_type='raw_output'").all().some(row=>{
    const value=JSON.parse(row.result_data);return value.report===raw && value.complete;
  }));
  const retry={db,parameters,reportOnly:true,nativeScan:()=>assert.fail('must reuse report'),llm:async()=>({ok:true,content:JSON.stringify({findings:[
    {file:'src/input.c',start_line:12,title:'Unchecked copy',reason:'Copy into a fixed buffer without checking capacity',cwe:'CWE-120'}]})})};
  await auditSources(task,retry);
  const first=db.prepare("SELECT id FROM scan_results WHERE result_type='source_finding'").get().id;
  await auditSources(task,retry);
  const rows=db.prepare("SELECT id FROM scan_results WHERE result_type='source_finding'").all();
  assert.deepEqual(rows,[{id:first}]);assert.equal(creates,1);
  coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.cscan_complete,true);assert.deepEqual(coverage.parse_errors,[]);
});

test('final source-access failure preserves raw evidence and never imports candidates',async t=>{
  const db=reportDb(t);
  const {config}=await protocol(t,'Source-Access: unavailable\n'+report);
  await auditSources({scan_task_id:'unavailable',target:'/src/project'},{db,parameters:{source_path:'/src/project'},
    nativeScan:(target,options)=>scanCscanTarget(target,{...options,config,llm:()=>assert.fail('explicit fields')})});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
  assert.ok(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='raw_output'").get().n>0);
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.cscan.state,'source_unavailable');
});

test('failed or cancelled scans retain completed subtask reports without parsing or importing',async t=>{
  for(const cancel of [false,true]) await t.test(cancel?'cancel':'failure',async t=>{
    const db=reportDb(t),controller=new AbortController();let polls=0;
    const client={create:async()=>({id:'91',status:'running'}),flow:async()=>{
      polls++;
      if(cancel && polls===2) {controller.abort();throw new Error('cancelled');}
      return {id:'91',status:polls===1?'running':'waiting',tasks:[{id:'t',flowId:'91',status:polls===1?'running':'failed',
        subtasks:[{id:'s',status:'finished',result:report}]}]};
    },report:()=>assert.fail('incomplete scan'),finish:()=>assert.fail('incomplete scan'),stop:async()=>true};
    const operation=auditSources({scan_task_id:'failed',target:'/src/project'},{db,parameters:{source_path:'/src/project'},signal:controller.signal,
      nativeScan:(target,options)=>scanCscanTarget(target,{...options,client,config:{pollMs:1,timeoutMs:3000},llm:()=>assert.fail('incomplete scan')})});
    if(cancel) await assert.rejects(operation,/取消/);else await operation;
    assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
    assert.ok(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='raw_output'").get().n>0);
    await assert.rejects(auditSources({scan_task_id:'failed',target:'/src/project'},{db,parameters:{source_path:'/src/project'},reportOnly:true}),/完整 CScan 报告/);
  });
});

test('cancellation or timeout during parsing keeps the completed report after releasing the remote worker',async t=>{
  for(const cancel of [false,true]) await t.test(cancel?'cancel':'timeout',async t=>{
    const db=reportDb(t),controller=new AbortController();let finished=false,creates=0;
    const raw='src/input.c line 12: Copy into a fixed buffer without checking capacity';
    const task={scan_task_id:'parse-interrupted',target:'/src/project'},parameters={source_path:'/src/project'};
    const client={create:async()=>{creates++;return {id:'91',status:'running'};},
      flow:async()=>({id:'91',status:'waiting',tasks:[{id:'t',status:'finished',subtasks:[]}]}),
      report:async()=>raw,finish:async()=>{finished=true;return true;},stop:()=>assert.fail('worker already released')};
    const operation=auditSources(task,{db,parameters,signal:controller.signal,
      nativeScan:(target,options)=>scanCscanTarget(target,{...options,client,config:{pollMs:1,timeoutMs:100},
        llm:async(_,options)=>{
          assert.equal(finished,true);
          return new Promise((resolve,reject)=>{
            options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});
            if(cancel) controller.abort();
          });
        }})});
    if(cancel) await assert.rejects(operation,/取消/);else await operation;
    const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
    assert.equal(coverage.cscan.state,cancel?'cancelled':'report_error');
    assert.ok(coverage.source_errors.some(error=>error.includes(cancel?'取消':'超时')));
    assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
    await auditSources(task,{db,parameters,reportOnly:true,llm:async()=>({ok:true,content:'{"findings":[]}'})});
    assert.equal(creates,1);
    assert.equal(JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis).cscan_complete,true);
  });
});

test('restart during report processing retains the complete report for manual retry without rescanning',async t=>{
  const db=reportDb(t),task={scan_task_id:'restart-report',target:'/src/project'},parameters={source_path:'/src/project'};
  await auditSources(task,{db,parameters,nativeScan:async()=>({...await parseNativeReport(report,task.target),flow_id:'91',finish_status:'acknowledged'})});
  const first=db.prepare("SELECT id FROM scan_results WHERE result_type='source_finding'").get().id;
  db.exec("CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,status TEXT,completed_at TEXT,error_message TEXT);INSERT INTO scan_tasks(scan_task_id,status) VALUES ('restart-report','RUNNING')");
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  coverage.cscan.state='parsing';
  db.prepare('UPDATE source_audits SET analysis=?').run(JSON.stringify(coverage));
  assert.equal(await recoverCscanAudits(db,{connect:async()=>({stop:()=>assert.fail('Flow already finished')})}),1);
  const recovered=db.prepare('SELECT * FROM scan_tasks').get();
  assert.equal(recovered.status,'FAILED');assert.match(recovered.error_message,/重新解析/);
  await auditSources(task,{db,parameters,reportOnly:true,nativeScan:()=>assert.fail('no new scan')});
  assert.deepEqual(db.prepare("SELECT id FROM scan_results WHERE result_type='source_finding'").all(),[{id:first}]);
});

test('failed batch import rolls back all findings and can retry from the saved report',async t=>{
  const db=reportDb(t),task={scan_task_id:'atomic',target:'/src/project'},parameters={source_path:'/src/project'};
  db.exec("CREATE TRIGGER reject_second BEFORE INSERT ON scan_results WHEN NEW.result_type='source_finding' AND json_extract(NEW.result_data,'$.file')='src/other.c' BEGIN SELECT RAISE(ABORT,'fixture write failure'); END");
  const markdown=report+'\n\n'+report.replace('src/input.c','src/other.c');
  await auditSources(task,{db,parameters,nativeScan:async()=>({...await parseNativeReport(markdown,task.target),flow_id:'91'})});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
  assert.equal(JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis).cscan.state,'import_error');
  db.exec('DROP TRIGGER reject_second');
  await auditSources(task,{db,parameters,reportOnly:true,llm:()=>assert.fail('explicit fields')});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,2);
});

test('one malformed model finding does not discard valid findings in the completed report',async t=>{
  const db=reportDb(t);
  const raw='src/input.c line 12: Copy into a fixed buffer without checking capacity';
  const {config}=await protocol(t,raw);
  const result=await auditSources({scan_task_id:'malformed-item',target:'/src/project'},{db,parameters:{source_path:'/src/project'},
    nativeScan:(target,options)=>scanCscanTarget(target,{...options,config,llm:async()=>({ok:true,content:JSON.stringify({findings:[
      {file:'src/input.c',start_line:12,title:'Unchecked copy',reason:'Copy into a fixed buffer without checking capacity'},null]})})})});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,1);
  assert.equal(result.outcomes.find(item=>item.tool_id==='report-parser').success,false);
});

test('mixed explicit and prose source sections are parsed without admitting web-only findings',async()=>{
  const prose='## Additional finding\nsrc/other.c line 8 reads freed memory.';
  const parsed=await parseNativeReport(report+'\n\n'+prose,'/src/project',{llm:async messages=>{
    assert.match(JSON.parse(messages[1].content).report,/Additional finding/);
    return {ok:true,content:JSON.stringify({vulnerabilities:[{name:'Use after free',file:'src/other.c',start_line:8,evidence:'reads freed memory.'}]})};
  }});
  assert.equal(parsed.findings.length,2);
  assert.equal(normalizeCscanReportedFinding(parsed.findings[1],parsed.markdown,'/src/project').title,'Use after free');
  assert.throws(()=>normalizeCscanReportedFinding({file:'https://example.test/a.c',start_line:1,title:'Web',reason:'evidence'},'https://example.test/a.c evidence','/src/project'),/路径无效/);
});

test('source report verification requires a separate in-scope runtime target',()=>{
  const pipeline={target:'http://192.0.2.40:8089/',config:JSON.stringify({task_scope:{}})};
  const finding={id:1,scan_task_id:'scan',result_data:JSON.stringify({evidence_origin:'cscan_report',file:'src/input.c'})};
  let parameters={cscan_target:'http://192.0.2.40:8089/'};
  const db={prepare:()=>({get:()=>({target:pipeline.target,parameters:JSON.stringify(parameters)})})};
  assert.equal(findingVerificationEntry(db,pipeline,finding).target,null);
  parameters.runtime_target='http://192.0.2.40:8089/';
  assert.equal(findingVerificationEntry(db,pipeline,finding).source,'declared_runtime_target');
  parameters.runtime_target='http://192.0.2.99/';
  assert.equal(findingVerificationEntry(db,pipeline,finding).target,null);
});

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
    else if(body.query.includes('createAssistant'))res.end(JSON.stringify({data:{createAssistant:{assistant:{id:'a1',flowId:'91',status:'waiting',useAgents:false}}}}));
    else if(body.query.includes('assistantLogs'))res.end(JSON.stringify({data:{assistantLogs:[{id:'l1',flowId:'91',assistantId:'a1',type:'assistant',message:'{"reports":[]}',appendPart:false}]}}));
    else if(body.query.includes('assistants('))res.end(JSON.stringify({data:{assistants:[{id:'a1',flowId:'91',status:'waiting',useAgents:false}]}}));
    else if(body.query.includes('CScanPayloadEvidence'))res.end(JSON.stringify({data:{tasks:[task],terminalLogs:[],messageLogs:[]}}));
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
  const result=await scanCscanTarget('/src/project',{notes:'重点检查输入长度',sourceLocation:'所选远端目录 /opt/example',config,llm:()=>assert.fail('explicit report fields need no second model')});
  assert.equal(result.report_source,'task_result');assert.equal(result.flow_id,'91');assert.equal(result.findings.length,1);
  const input=calls[0].variables.input;
  assert.match(input,/\/src\/project/);assert.match(input,/重点检查输入长度/);assert.match(input,/API 仅提交路径/);
  assert.match(input,/使用当前 Flow 已分配的 vxcontrol\/kali-linux 容器/);
  assert.match(input,/不使用其他 Flow 的容器/);
  assert.match(input,/禁止调用 memorist/);
  assert.match(input,/不得通过终端查找记忆目录、数据库、环境变量或 Python 包/);
  assert.match(input,/将上述容器与记忆约束传递给所有规划、执行和子任务代理/);
  assert.match(input,/对每条有明确源码定位和依据的漏洞，生成与该漏洞一一对应/);
  assert.match(input,/Payload-For: 文件路径:起止行/);
  assert.match(input,/在该漏洞的原任务和子任务报告中保留完整载荷正文/);
  assert.match(input,/载荷只生成、不执行/);
  assert.doesNotMatch(input,/findings\.json|snapshot_id|SHA256/);
  assert.match(input,/所选远端目录 \/opt\/example/);
  assert.ok(calls.some(c=>c.query.includes('CScanReport')));assert.ok(calls.at(-1).query.includes('finishFlow'));
});

test('source paths with spaces reach the remote Flow through legacy and agent audit inputs',async t=>{
  for(const key of ['source_path','cscan_target']) await t.test(key,async t=>{
    const source=key==='source_path'?'/src/my project':'/var/www/my project';
    const db=new Database(':memory:');t.after(()=>db.close());
    db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT)');
    const {calls,config}=await protocol(t,'Source-Access: available\n'+report);
    const result=await auditSources({scan_task_id:'spaced-path',target:source},{db,
      parameters:{[key]:source,input_kind:key==='source_path'?'source':'agent'},
      nativeScan:(target,options)=>scanCscanTarget(target,{...options,config,
        llm:()=>assert.fail('explicit report fields need no second model')})});
    assert.ok(result.outcomes.length>0);
    assert.ok(result.outcomes.every(outcome=>outcome.success),JSON.stringify(result.outcomes));
    assert.equal(calls.filter(call=>call.query.includes('createFlow')).length,1);
    assert.ok(calls.find(call=>call.query.includes('createFlow')).variables.input.includes(source));
    assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,1);
    assert.equal(JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis).cscan_complete,true);
  });
});

test('allowing spaces in source paths preserves invalid path and network target rejection',()=>{
  for(const target of ['/src/my project/../private','/src/my\tproject','/src/my\nproject','/src/my\\project',
    'http://example.invalid/my project','example .invalid','192.0.2.40: 8089'])
    assert.throws(()=>cscanTarget(target),target);
});

test('remote target and audit requirements go to the Flow together with the exact scope',async t=>{
  const {calls,config}=await protocol(t,'Source-Access: available\n'+report);
  const scope=normalizeTaskScope({task_scope:{excludes:['http://192.0.2.40:8089/private/']}},'http://192.0.2.40:8089/');
  const result=await scanCscanTarget('http://192.0.2.40:8089/',{notes:'源码在靶机 /var/www/project，使用既有授权连接',scope,config});
  assert.equal(result.source_access_reported,'available');
  const input=calls[0].variables.input;
  assert.match(input,/http:\/\/192\.0\.2\.40:8089\//);assert.match(input,/靶机网络目标/);
  assert.match(input,/\/var\/www\/project/);assert.ok(input.includes(JSON.stringify(scope)));
  assert.match(input,/不得用历史任务、记忆召回、旧快照目录或其他本机目录替代/);
  assert.match(input,/必须重新核实本次源码来源/);
  assert.match(input,/使用当前 Flow 已分配的 vxcontrol\/kali-linux 容器/);
  assert.match(input,/禁止调用 memorist/);
  assert.match(input,/Payload-Status: unavailable 并逐项列出缺失条件/);
  assert.match(input,/无源码或无明确漏洞时不生成载荷/);
  assert.doesNotMatch(input,/历史信息只能提供线索/);
  assert.doesNotMatch(input,/目标是 CScan 执行环境中的文件或目录路径|先确认该路径在执行容器中/);
  assert.equal(result.findings.length,1);
});

test('per-finding payload drafts remain report artifacts and do not become extra source findings',async t=>{
  const markdown='Source-Access: available\n'+report+'\n'+[
    'Payload-For: src/input.c:12-12','Payload-Status: draft','Payload-Language: python','Payload-Content:',
    '```python','print("fixture boundary input")','## This is script text, not another finding',
    'File: invented.c','Line: 99','Evidence: script comment','```',
    'Payload-Usage: Review before use','Payload-Prerequisites: Confirm the input protocol',
    'Payload-Baseline: normal input','Payload-Expected: Compare with baseline, not an observed success',
    'Payload-Limitations: Not executed',
  ].join('\n');
  const {config}=await protocol(t,markdown);
  const result=await scanCscanTarget('/src/project',{config,llm:()=>assert.fail('explicit finding fields suffice')});
  assert.equal(result.findings.length,1);assert.equal(result.findings[0].file,'src/input.c');
  assert.equal(result.findings[0].reason,'Copy into a fixed buffer without checking capacity');
  assert.equal(result.findings[0].suggestion,'Enforce the buffer capacity');
  assert.ok(result.markdown.includes('print("fixture boundary input")'),'the original payload text is retained for collection');
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
  const config={...cscanConfig({}),scanTimeoutMs:60,pollMs:10};let stopped=0;let reportSignal;
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

test('report retry API reuses retained evidence and finding IDs, rejects incomplete, active and foreign scans',async t=>{
  const {env,calls}=await protocol(t);
  const old=Object.fromEntries(Object.keys(env).map(k=>[k,process.env[k]]));Object.assign(process.env,env);
  t.after(()=>{for(const [key,value] of Object.entries(old)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  const db=getDb(':memory:');t.after(closeDb);
  const directory=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for(const name of (await readdir(directory)).sort()) {if(name.includes('import')) continue;const m=await import(directory+name);(m.default || m.up)(db);}
  db.prepare("INSERT OR IGNORE INTO users(username,password,role) VALUES ('alice','fixture','user'),('bob','fixture','user')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,parameters,created_by,started_at,completed_at) VALUES ('report-retry','/src/project','source_scan','FAILED',?,'alice','2026-01-01T00:00:00Z','2026-01-01T00:01:00Z')")
    .run(JSON.stringify({source_path:'/src/project'}));
  const task=db.prepare('SELECT * FROM scan_tasks').get();
  await auditSources(task,{db,parameters:JSON.parse(task.parameters),nativeScan:async()=>({markdown:report,findings:[],parse_errors:['fixture parse failure'],flow_id:'91'})});
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user'] || 'alice',role:'user'};next();});
  app.use('/scans',scanRoutes(db));
  const base=await listen(t,http.createServer(app));
  const request=async(suffix,method='POST',user='alice')=>{
    const response=await fetch(base+'/scans/report-retry'+suffix,{method,headers:{'content-type':'application/json','x-user':user},...(method==='POST'?{body:'{}'}:{})});
    return {status:response.status,body:await response.json()};
  };
  const copyId=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('report-retry','source_file_copy',?)")
    .run(JSON.stringify({path:'/work/src/main.c',sha256:'fixture-hash',content:'actual source body'})).lastInsertRowid);
  assert.equal((await request('/source-file?id='+copyId,'GET','bob')).status,403);
  assert.equal((await request('/source-file?id='+copyId,'GET')).body.data.content,'actual source body');
  assert.equal((await request('/source-file?id=999999','GET')).status,404);
  const detail=(await request('','GET')).body.data;
  assert.equal(detail.source_files[0].id,copyId);assert.equal(detail.source_files[0].content,undefined);
  assert.ok(!detail.results.some(row=>row.result_type==='source_file_copy'));
  assert.equal((await request('/reparse','POST','bob')).status,403);
  assert.equal((await request('','GET')).body.data.can_reparse_report,true);
  db.prepare("UPDATE scan_tasks SET status='RUNNING'").run();
  assert.equal((await request('/reparse')).status,409);
  assert.equal((await request('/generate-playbook')).status,400);
  db.prepare("UPDATE scan_tasks SET status='FAILED'").run();
  for(let attempt=0;attempt<2;attempt++) {
    assert.equal((await request('/reparse')).status,202);
    const deadline=Date.now()+3000;
    while(Date.now()<deadline && db.prepare('SELECT status FROM scan_tasks').get().status==='RUNNING') await new Promise(resolve=>setTimeout(resolve,10));
    assert.equal(db.prepare('SELECT status FROM scan_tasks').get().status,'COMPLETED');
  }
  assert.equal(calls.length,0,'report retry must not contact CScan');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,1);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM source_audits').get().n,1);
  assert.equal(db.prepare('SELECT started_at FROM scan_tasks').get().started_at,task.started_at);
  db.prepare("DELETE FROM scan_results WHERE result_type='raw_output'").run();
  assert.equal((await request('/reparse')).status,409);
  assert.equal((await request('','GET')).body.data.can_reparse_report,false);
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
