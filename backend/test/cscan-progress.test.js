import test from 'node:test';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import Database from 'better-sqlite3';
import {createCscanProgressParser,cscanReportHash} from '../src/services/cscanProgress.js';
import {scanCscanTarget,normalizeCscanReportedFinding,parseNativeReport} from '../src/services/cscanNative.js';
import {auditSources} from '../src/services/sourceAudit.js';
import {sourceScanPreview} from '../src/services/sourceScanResults.js';

const prose='In src/input.c at line 12, Copy into a fixed buffer without checking capacity. The input limit remains unknown.';
const finding={file:'src/input.c',start_line:12,title:'Unchecked copy',reason:'Copy into a fixed buffer without checking capacity',severity:'high',cwe:'CWE-120'};
const finalReport='Source-Access: available\n## Unchecked copy\nFile: src/input.c\nLine: 12\nSeverity: high\nCWE: CWE-120\nEvidence: '+finding.reason;
const raw=(report=prose,id='s1')=>({report,status:'finished',report_source:'subtask_result',source_task_ids:['t1'],source_subtask_ids:[id]});
function deferred() {
  let resolve,reject;
  const promise=new Promise((done,fail)=>{resolve=done;reject=fail;});
  return {promise,resolve,reject};
}
async function until(predicate) {
  for(let i=0;i<200;i++) {if(predicate())return;await delay(5);}
  assert.fail('progress did not arrive within the test deadline');
}
function parser(t,options={}) {
  const writes=[];
  const progress=createCscanProgressParser({
    parse:async()=>({findings:[finding],parse_errors:[]}),
    normalize:(finding,report)=>normalizeCscanReportedFinding(finding,report,'/src/project'),
    onReport:async value=>{writes.push(value);},...options,
  });
  t.after(()=>progress.close());
  return {progress,writes};
}

test('stage reports prefer model interpretation even with explicit fields and retain field extraction during model outages',async()=>{
  let calls=0;
  const parsed=await parseNativeReport(finalReport,'/src/project',{phase:'progress',split:false,llm:async messages=>{
    calls++;assert.equal(JSON.parse(messages[1].content).report_phase,'progress');
    return {ok:true,content:JSON.stringify({findings:[{...finding,title:'Model-organized finding'}]})};
  }});
  assert.equal(calls,1);assert.equal(parsed.findings[0].title,'Model-organized finding');
  const fallback=await parseNativeReport(finalReport,'/src/project',{phase:'progress',split:false,llm:async()=>({ok:false})});
  assert.equal(fallback.findings[0].file,finding.file);assert.ok(fallback.parse_errors.length);
});

test('completed prose subtasks become model-derived previews while polling continues and official findings wait for completion',async t=>{
  const db=new Database(':memory:'),controller=new AbortController(),model=deferred();
  let job;
  t.after(async()=>{controller.abort();if(job)await job.catch(()=>{});db.close();});
  db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT)');
  let polls=0,modelCalls=0,allowFinish=false;
  const client={create:async()=>({id:'91',status:'running'}),flow:async()=>{
    polls++;
    return {id:'91',status:allowFinish?'waiting':'running',tasks:[{id:'t1',flowId:'91',status:allowFinish?'finished':'running',
      subtasks:[{id:'s1',status:'finished',result:prose},{id:'s2',status:allowFinish?'finished':'running',result:''}]}]};
  },report:async()=>finalReport,finish:async()=>true,stop:async()=>true};
  const task={scan_task_id:'progress',scan_type:'source_scan',status:'RUNNING',target:'/src/project'};
  job=auditSources(task,{db,signal:controller.signal,parameters:{source_path:task.target},
    nativeScan:(target,options)=>scanCscanTarget(target,{...options,client,config:{pollMs:2,timeoutMs:5000},llm:async messages=>{
      const input=JSON.parse(messages[1].content);assert.equal(input.report_phase,'progress');assert.equal(input.report,prose);
      modelCalls++;return model.promise;
    }})});
  await until(()=>modelCalls===1);
  const firstPoll=polls;await until(()=>polls>=firstPoll+3);
  assert.equal(modelCalls,1,'repeated polling must not issue duplicate model requests');
  model.resolve({ok:true,content:JSON.stringify({vulnerabilities:[{...finding,name:finding.title,evidence:finding.reason}]})});
  const rows=()=>db.prepare('SELECT * FROM scan_results ORDER BY id').all();
  await until(()=>sourceScanPreview(task,rows()).findings.length===1);
  const preview=sourceScanPreview(task,rows()).findings[0];
  assert.equal(preview.file,finding.file);assert.equal(preview.id,undefined);assert.equal(preview.runtime_verified,false);
  assert.deepEqual(preview.source_subtask_ids,['s1']);
  assert.equal(rows().filter(row=>row.result_type==='source_finding').length,0);
  allowFinish=true;
  const result=await job;
  assert.ok(result.outcomes.every(item=>item.success),JSON.stringify(result.outcomes));
  assert.equal(rows().filter(row=>row.result_type==='source_finding').length,1);
  assert.equal(modelCalls,1,'the final explicit report does not require a second model extraction');
});

test('progress failures retry at most three times per report version and new report content can be parsed',async t=>{
  let calls=0;
  const {progress,writes}=parser(t,{parse:async report=>{calls++;if(report===prose)throw new Error('fixture outage');return {findings:[finding],parse_errors:[]};}});
  for(let i=1;i<=3;i++) {progress.observe(raw());progress.start();await until(()=>writes.length===i);}
  const failed=progress.observe(raw());progress.start();await delay(10);
  assert.equal(calls,3);assert.equal(failed.progress_analysis.state,'error');assert.ok(failed.progress_analysis.parse_errors.length);
  progress.observe(raw(prose+' New report version.'));progress.start();await until(()=>writes.length===4);
  assert.equal(calls,4);assert.equal(writes.at(-1).progress_analysis.state,'complete');
});

test('a successful empty extraction is cached without repeated model calls',async t=>{
  let calls=0;
  const {progress,writes}=parser(t,{parse:async()=>{calls++;return {findings:[],parse_errors:[]};}});
  progress.observe(raw());progress.start();await until(()=>writes.length===1);
  for(let i=0;i<4;i++){progress.observe(raw());progress.start();}
  await delay(5);assert.equal(calls,1);assert.deepEqual(writes[0].progress_analysis.findings,[]);
});

test('fabricated paths and evidence are rejected; repeated valid findings merge their source IDs',async t=>{
  let calls=0;
  const {progress,writes}=parser(t,{parse:async()=>{
    if(++calls>1)throw new Error('fixture outage after a partial extraction');
    return {findings:[finding,{...finding,file:'invented.c'},{...finding,reason:'invented evidence'}],parse_errors:[]};
  }});
  progress.observe(raw());progress.start();await until(()=>writes.length===1);
  const analysis=writes[0].progress_analysis;
  assert.equal(analysis.findings.length,1);assert.ok(analysis.parse_errors.length);
  const other={...writes[0],source_subtask_ids:['s2']};
  const task={scan_type:'source_scan',status:'RUNNING',target:'/src/project'};
  const preview=sourceScanPreview(task,[writes[0],other].map(value=>({result_type:'raw_output',result_data:JSON.stringify(value)})));
  assert.equal(preview.findings.length,1);assert.deepEqual(preview.findings[0].source_subtask_ids,['s1','s2']);
  assert.equal(preview.findings[0].id,undefined);
  const stale={...writes[0],report:'New report without file evidence'};
  assert.equal(sourceScanPreview(task,[{result_type:'raw_output',result_data:JSON.stringify(stale)}]).findings.length,0);
  progress.observe(raw());progress.start();await until(()=>writes.length===2);
  assert.equal(writes[1].progress_analysis.findings.length,1,'a failed retry preserves already validated preview evidence');
});

test('a changed report discards late results for its previous content',async t=>{
  const old=deferred(),next=deferred();let calls=0;
  const {progress,writes}=parser(t,{parse:report=>{calls++;return report===prose?old.promise:next.promise;}});
  progress.observe(raw());progress.start();await until(()=>calls===1);
  const updated=prose+' Updated source report.';progress.observe(raw(updated));progress.start();
  old.resolve({findings:[finding],parse_errors:[]});await until(()=>calls===2);
  assert.equal(writes.length,0);
  next.resolve({findings:[finding],parse_errors:[]});await until(()=>writes.length===1);
  assert.equal(writes[0].report,updated);assert.equal(writes[0].progress_analysis.report_hash,cscanReportHash(updated));
});

test('cancellation and timeout bound non-cooperative model calls and suppress late writes',async t=>{
  for(const mode of ['cancel','timeout'])await t.test(mode,async t=>{
    const controller=new AbortController(),model=deferred();let calls=0;
    const {progress,writes}=parser(t,{signal:controller.signal,timeoutMs:20,parse:()=>{calls++;return model.promise;}});
    progress.observe(raw());progress.start();await until(()=>calls===1);
    if(mode==='cancel')controller.abort();
    else await until(()=>writes.length===1);
    const before=writes.length;model.resolve({findings:[finding],parse_errors:[]});await delay(10);
    assert.equal(writes.length,before);assert.equal(before,mode==='cancel'?0:1);
  });
});

test('unfinished reports and unavailable source are not sent to the model; oversized reports retain an explicit gap',async t=>{
  let calls=0;
  const {progress}=parser(t,{maxBytes:256,parse:async()=>{calls++;return {findings:[],parse_errors:[]};}});
  assert.equal(progress.observe({...raw(),status:'running'}).progress_analysis,undefined);
  assert.equal(progress.observe(raw('Source-Access: unavailable\n'+prose)).progress_analysis,undefined);
  const oversized=progress.observe(raw('x'.repeat(257)));progress.start();await delay(5);
  assert.equal(calls,0);assert.equal(oversized.report.length,257);assert.match(oversized.progress_analysis.parse_errors[0],/上限/);
});

test('the progress queue has a source-count bound and retains over-limit reports for final processing',async t=>{
  let calls=0;
  const {progress,writes}=parser(t,{maxReports:2,parse:async()=>{calls++;return {findings:[],parse_errors:[]};}});
  progress.observe(raw(prose,'s1'));progress.observe(raw(prose,'s2'));
  const overLimit=progress.observe(raw(prose,'s3'));progress.start();await until(()=>writes.length===2);
  assert.equal(calls,2);assert.equal(overLimit.report,prose);assert.match(overLimit.progress_analysis.parse_errors[0],/上限/);
});
