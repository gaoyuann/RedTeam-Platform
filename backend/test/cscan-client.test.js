import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {cscanConfig,createCscanClient,stageCscanSource,readCscanReport,runCscan} from '../src/services/cscanClient.js';
import {cscanFixture} from './helpers/cscanFixture.js';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {parseCscanMarkdown} from '../src/services/cscanReport.js';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(),'rt-cscan-'));
  t.after(async()=>{await chmod(root,0o700);await rm(root,{recursive:true,force:true});});
  const sourcesDir = join(root,'sources'),workDir = join(root,'work');
  await mkdir(sourcesDir);await mkdir(workDir);
  const content = 'void copy(char *input) {\n char buffer[8]; strcpy(buffer,input);\n}\n';
  const document = {path:'lib/input.c',content,start_line:1,end_line:4,sha256:createHash('sha256').update(content).digest('hex')};
  const source = {snapshot_id:'fixture-version',documents:[document],files:[{...document,content:undefined}],skipped:[]};
  return {source,config:{...cscanConfig({}),sourcesDir,workDir,pollMs:10,timeoutMs:1000,requestTimeoutMs:200,createTimeoutMs:200,token:'fixture-token'}};
}

async function server(t,handler) {
  const app = http.createServer(async(req,res)=>{
    let body = '';
    for await(const chunk of req) body += chunk;
    try {await handler(req,res,JSON.parse(body));}
    catch(error) {res.writeHead(500);res.end(JSON.stringify({error:error.message}));}
  });
  await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{app.closeAllConnections();await new Promise(resolve=>app.close(resolve));});
  return 'http://127.0.0.1:' + app.address().port + '/api/v1/graphql';
}

test('CScan stages immutable snapshot, creates once, polls and reads version-bound structured report',async t=>{
  const {source,config} = await fixture(t),requests=[],progress=[];
  let sourceKey;
  config.apiUrl = await server(t,async(req,res,body)=>{
    requests.push(body.query);assert.equal(req.headers.authorization,'Bearer fixture-token');
    assert.equal(req.url,'/api/v1/graphql');res.setHeader('content-type','application/json');
    if(body.query.includes('createFlow')) {
      sourceKey = body.variables.input.match(/\/src\/(rt-[\w-]+)/)[1];
      assert.equal(await readFile(join(config.sourcesDir,sourceKey,'lib/input.c'),'utf8'),source.documents[0].content);
      assert.match(body.variables.input,/Do not perform network scanning/);
      assert.match(body.variables.input,/使用当前 Flow 已分配的 vxcontrol\/kali-linux 容器/);
      assert.match(body.variables.input,/禁止调用 memorist/);
      assert.match(body.variables.input,/对每条有明确源码定位和依据的漏洞，生成与该漏洞一一对应/);
      assert.match(body.variables.input,/Payload-Status: draft 或 unavailable/);
      assert.match(body.variables.input,/fixture-version/);
      await mkdir(join(config.workDir,'flow-12'));
      await writeFile(join(config.workDir,'flow-12','findings.json'),JSON.stringify({snapshot_id:source.snapshot_id,
        findings:[{file:'lib/input.c',start_line:2,title:'Unchecked input',reason:'No bounds check'}],
        coverage:{reviewed_files:['lib/input.c'],omitted_files:[],complete:true}}));
      await writeFile(join(config.workDir,'flow-12','report.md'),'Fixture report');
      res.end(JSON.stringify({data:{createFlow:{id:'12',status:'running'}}}));
    } else res.end(JSON.stringify({data:{flow:{id:'12',status:'finished'},tasks:[{id:'1',flowId:'12',status:'finished',subtasks:[]}]}}));
  });
  const result = await runCscan(source,{config,onProgress:item=>progress.push(item)});
  assert.equal(result.flow_id,'12');assert.equal(result.markdown,'Fixture report');
  assert.equal(result.findings.length,1);assert.equal(requests.length,2);
  assert.deepEqual(progress.find(p=>p.task_progress)?.task_progress,{total:1,finished:1,failed:0,running:0});
  assert.deepEqual(progress.map(p=>p.state),['submitting','running','finished','finished']);
  assert.equal(progress[0].submission_uncertain,true);
  const staged = await stageCscanSource(source,config);
  assert.notEqual(staged.key,sourceKey,'a fresh scan cannot see stale source or reports');
});

test('CScan HTTP and GraphQL failures do not disclose credentials or retry create mutations',async t=>{
  for(const mode of ['http','graphql','json']) {
    const {source,config} = await fixture(t);let calls = 0;
    const progress = [];
    config.apiUrl = await server(t,(req,res)=>{
      calls++;
      if(mode==='http') {res.writeHead(401);res.end('fixture-token');}
      else res.end(mode==='graphql'?JSON.stringify({errors:[{message:'fixture-token'}]}):'fixture-token');
    });
    await assert.rejects(runCscan(source,{config,onProgress:p=>progress.push(p)}),error=>{
      assert.doesNotMatch(error.message,/fixture-token/);return true;
    });
    assert.equal(calls,1);assert.equal(progress.at(-1).submission_uncertain,true);
  }
});

test('CScan cancellation and deadline stop the known remote flow without using the aborted signal',async t=>{
  for(const kind of ['cancel','timeout','waiting','failed']) {
    const {source,config} = await fixture(t),controller = new AbortController(),stops=[],progress=[];
    config.timeoutMs=35;
    const client = {
      create:async()=>({id:'9',status:kind==='waiting'?'waiting':kind==='failed'?'failed':'running'}),
      flow:async()=>({id:'9',status:kind==='waiting'?'waiting':'running',tasks:[{id:'1',status:'waiting',subtasks:[]}]}),
      stop:async(id,options)=>{assert.equal(options,undefined);stops.push(id);},
    };
    // Exercise deadline/stop semantics without letting unrelated filesystem
    // scheduling consume the short test deadline before a Flow is created.
    await assert.rejects(runCscan(source,{config,client,signal:controller.signal,
      stage:async()=>({key:'fixture',containerPath:'/src/fixture'}),onProgress:p=>{
      progress.push(p);if(kind==='cancel' && p.state==='running') controller.abort();
    }}),/取消|超时|等待人工输入|扫描失败/);
    assert.deepEqual(stops,kind==='failed'?[]:['9']);
    assert.equal(progress.at(-1).stop_status,kind==='failed'?'not_requested':'acknowledged');
  }
});

test('CScan records unconfirmed cancellation; an already-cancelled scan never stages or creates a flow',async t=>{
  const {source,config} = await fixture(t),controller = new AbortController(),progress=[];
  controller.abort();
  await assert.rejects(runCscan(source,{config,signal:controller.signal,
    stage:()=>assert.fail('must not stage'),client:{create:()=>assert.fail('must not create')}}),/取消/);
  await assert.rejects(runCscan(source,{config,onProgress:p=>progress.push(p),client:{
    create:async()=>({id:'3',status:'waiting'}),flow:async()=>({id:'3',status:'waiting',tasks:[{status:'waiting',subtasks:[]}]}),
    stop:async()=>{throw new Error('unreachable');},
  }}),/等待人工输入/);
  assert.equal(progress.at(-1).stop_status,'unconfirmed');
});

test('CScan validates source hashes and paths, report version, symlinks and size',async t=>{
  const {source,config} = await fixture(t);
  for(const doc of [{...source.documents[0],path:'../outside.c'},{...source.documents[0],sha256:'wrong'}])
    await assert.rejects(stageCscanSource({...source,documents:[doc]},config),/路径或快照哈希/);
  const directory=join(config.workDir,'flow-4');await mkdir(directory);
  const target=join(directory,'findings.json');
  await writeFile(target,JSON.stringify({snapshot_id:'other-version',findings:[]}));
  await assert.rejects(readCscanReport(config,'4',source),/版本/);
  await assert.rejects(readCscanReport(config,'../4',source),/ID/);
  await writeFile(target,'x'.repeat(2*1024*1024+1));
  await assert.rejects(readCscanReport(config,'4',source),/大小/);
  await symlink(directory,join(config.workDir,'flow-5'));
  await assert.rejects(readCscanReport(config,'5',source),/符号链接/);
  await rm(target);await symlink(join(directory,'missing'),target);
  await assert.rejects(readCscanReport(config,'4',source));
});

test('CScan request timeout and missing credentials fail explicitly',async t=>{
  const {config}=await fixture(t);config.requestTimeoutMs=25;config.createTimeoutMs=25;
  await assert.rejects(createCscanClient({...config,token:'',tokenFile:''}),/凭据|配置/);
  config.apiUrl=await server(t,()=>{});
  const client=await createCscanClient(config);
  await assert.rejects(client.create('fixture'),/超时/);
});

test('CScan environment self-check authenticates without creating a Flow or requiring local SAST',async t=>{
  const fixture=await cscanFixture(t);
  const result=await promisify(execFile)(process.execPath,[fileURLToPath(new URL('../scripts/check-source-environment.js',import.meta.url)),
    '--source-kind','http','--api'],{env:{...process.env,...fixture.env},timeout:5000});
  const report=JSON.parse(result.stdout);
  assert.equal(report.passed,true);assert.equal(fixture.counts.created,0);
  assert.equal(report.checks.find(c=>c.name==='cscan_api').passed,true);
  assert.equal(report.checks.some(c=>['cppcheck','flawfinder','sast_image'].includes(c.name)),false);
});

test('CScan requires a successful stop response rather than treating HTTP 200 as confirmation',async t=>{
  const {config}=await fixture(t);
  config.apiUrl=await server(t,(req,res)=>res.end(JSON.stringify({data:{stopFlow:null}})));
  const client=await createCscanClient(config);
  await assert.rejects(client.stop('1'),/未确认停止/);
});

test('CScan staging failure is not an uncertain submission and completed flows are not stopped on report errors',async t=>{
  const {source,config}=await fixture(t),progress=[];
  const client={create:async()=>({id:'11',status:'finished'}),
    flow:async()=>({id:'11',status:'finished',tasks:[{status:'finished',subtasks:[]}]}),
    stop:()=>assert.fail('must not stop an already finished Flow')};
  await assert.rejects(runCscan(source,{config,client,onProgress:p=>progress.push(p),stage:async()=>{throw new Error('staging failed');}}),/staging failed/);
  assert.equal(progress.at(-1).submission_uncertain,false);
  await assert.rejects(runCscan(source,{config,client,onProgress:p=>progress.push(p),readReport:async()=>{throw new Error('report missing');}}),/report missing/);
  assert.equal(progress.at(-1).state,'report_error');assert.equal(progress.at(-1).stop_status,'not_requested');
});

const markdownReport = '## Unchecked copy\n- File: `lib/input.c`\n- Line: 2\n- Severity: high\n- CWE: CWE-120\n- Evidence: Unbounded copy into a fixed buffer\n- Preconditions: Caller-controlled input remains to be verified\n- Remediation: Enforce the destination capacity\n';

test('waiting without tasks fails promptly after confirmed polls and stops the original Flow once',async t=>{
  const {source,config}=await fixture(t),progress=[];
  let creates=0,polls=0,stops=0;
  config.apiUrl=await server(t,(req,res,body)=>{
    if(body.query.includes('createFlow')) {
      creates++;res.end(JSON.stringify({data:{createFlow:{id:'82',status:'running'}}}));
    } else if(body.query.includes('stopFlow')) {
      stops++;assert.equal(body.variables.id,'82');
      res.end(JSON.stringify({data:{stopFlow:'success'}}));
    } else {
      polls++;res.end(JSON.stringify({data:{flow:{id:'82',status:'waiting'},tasks:[]}}));
    }
  });
  await assert.rejects(runCscan(source,{config,onProgress:p=>progress.push(p),
    stage:async()=>({key:null,containerPath:'/src/fixture'}),
    readReport:()=>assert.fail('no task can produce a report')}),/未创建扫描任务/);
  assert.equal(creates,1);assert.equal(polls,3);assert.equal(stops,1);
  assert.equal(progress.at(-1).flow_id,'82');
  assert.equal(progress.at(-1).stop_status,'acknowledged');
});

test('transient empty waiting states do not reject a Flow that starts or completes',async t=>{
  const {source,config}=await fixture(t);
  for(const statuses of [
    ['waiting','waiting','running','waiting','waiting','finished'],
    ['waiting','finished'],
  ]) {
    let polls=0;
    const result=await runCscan(source,{config,
      stage:async()=>({key:null,containerPath:'/src/fixture'}),
      readReport:async()=>({findings:[],markdown:'Completed'}),
      client:{
        create:async()=>({id:'83',status:'waiting'}),
        flow:async()=>{
          const status=statuses[polls++];
          return {id:'83',status:status==='finished'?'waiting':status,
            tasks:status==='finished'?[{status:'finished',subtasks:[]}]:[]};
        },
        finish:async()=>{},
        stop:()=>assert.fail('successful Flow must not be stopped'),
      }});
    assert.equal(result.flow_id,'83');assert.equal(polls,statuses.length);
  }
});

test('upstream waiting plus finished task imports native Markdown then finalizes Flow',async t=>{
  const {source,config}=await fixture(t),calls=[];
  config.apiUrl=await server(t,async(req,res,body)=>{
    calls.push(body.query);res.setHeader('content-type','application/json');
    if(body.query.includes('createFlow')) {
      await mkdir(join(config.workDir,'flow-71'));
      await writeFile(join(config.workDir,'flow-71','report.md'),markdownReport);
      res.end(JSON.stringify({data:{createFlow:{id:'71',status:'waiting'}}}));
    } else if(body.query.includes('finishFlow')) res.end(JSON.stringify({data:{finishFlow:'success'}}));
    else res.end(JSON.stringify({data:{flow:{id:'71',status:'waiting'},tasks:[{id:'1',flowId:'71',status:'finished',subtasks:[{id:'1',status:'finished'}]}]}}));
  });
  const result=await runCscan(source,{config});
  assert.equal(result.report_format,'markdown');assert.equal(result.findings.length,1);
  assert.equal(result.findings[0].file,'lib/input.c');assert.equal(result.findings[0].start_line,2);
  assert.equal(result.finish_status,'acknowledged');assert.equal(result.coverage,null);
  assert.equal(calls.length,3);assert.ok(calls.at(-1).includes('finishFlow'));
});

test('native database task result is used when no report file was generated',async t=>{
  const {source,config}=await fixture(t);let finished=0;
  config.apiUrl=await server(t,(req,res,body)=>{
    res.setHeader('content-type','application/json');
    const task={id:'1',flowId:'72',status:'finished',subtasks:[],result:markdownReport};
    if(body.query.includes('createFlow')) res.end(JSON.stringify({data:{createFlow:{id:'72',status:'running'}}}));
    else if(body.query.includes('finishFlow')) {finished++;res.end(JSON.stringify({data:{finishFlow:'success'}}));}
    else if(body.query.includes('CScanReport')) res.end(JSON.stringify({data:{tasks:[task]}}));
    else res.end(JSON.stringify({data:{flow:{id:'72',status:'waiting'},tasks:[task]}}));
  });
  const result=await runCscan(source,{config});
  assert.equal(result.report_source,'task_result');assert.equal(result.findings.length,1);assert.equal(finished,1);
});

test('waiting with failed task is not completion; malformed JSON never falls back to Markdown',async t=>{
  const {source,config}=await fixture(t),stops=[];
  await assert.rejects(runCscan(source,{config,client:{create:async()=>({id:'73',status:'waiting'}),
    flow:async()=>({id:'73',status:'waiting',tasks:[{status:'failed',subtasks:[]}]}),stop:async id=>stops.push(id)},
    readReport:()=>assert.fail('failed tasks cannot produce successful scan reports')}),/任务失败/);
  assert.deepEqual(stops,['73']);
  await mkdir(join(config.workDir,'flow-74'));
  await writeFile(join(config.workDir,'flow-74','findings.json'),'{malformed');
  await writeFile(join(config.workDir,'flow-74','report.md'),markdownReport);
  await assert.rejects(readCscanReport(config,'74',source),/不是有效 JSON/);
});

test('Markdown parser supports explicit fields and tables, ignores prose and code as findings',()=>{
  const table='| Title | File | Line | Evidence | Severity |\n| --- | --- | --- | --- | --- |\n| Copy issue | lib/input.c | 2-3 | Fixed buffer copy | high |';
  const result=parseCscanMarkdown(markdownReport+'\n'+table,'v1');
  assert.equal(result.findings.length,2);assert.equal(result.findings[1].end_line,3);
  assert.equal(parseCscanMarkdown('The source looks safe.\n```\n'+markdownReport+'\n```','v1').findings.length,0);
  assert.equal(result.coverage,null);
});

test('Markdown preserves underscore filenames and bold labels, excluding indented and nested fenced code',()=>{
  const report='## Candidate\n- **File:** `_input.c`\n- **Line**: 2\n- **Evidence:** Unchecked copy';
  const result=parseCscanMarkdown(report,'v1');
  assert.equal(result.findings.length,1);assert.equal(result.findings[0].file,'_input.c');
  assert.equal(result.findings[0].reason,'Unchecked copy');
  const indented='## Example\n    File: _input.c\n    Line: 2\n    Evidence: Code example';
  assert.equal(parseCscanMarkdown(indented,'v1').findings.length,0);
  const fenced='````markdown\n```c\n'+report+'\n```\n````';
  assert.equal(parseCscanMarkdown(fenced,'v1').findings.length,0);
});

test('completed scan report survives an unconfirmed finishFlow and records the cleanup gap',async t=>{
  const {source,config}=await fixture(t),progress=[];
  const report={snapshot_id:source.snapshot_id,findings:[],coverage:{reviewed_files:['lib/input.c'],omitted_files:[],complete:true}};
  const result=await runCscan(source,{config,onProgress:p=>progress.push(p),readReport:async()=>report,client:{
    create:async()=>({id:'75',status:'running'}),flow:async()=>({id:'75',status:'waiting',tasks:[{status:'finished',subtasks:[]}]}),
    finish:async()=>{throw new Error('timeout');},stop:()=>assert.fail('must retain the completed report')}});
  assert.equal(result.finish_status,'unconfirmed');assert.equal(progress.at(-1).flow_status,'waiting');
  assert.equal(result.snapshot_id,source.snapshot_id);
});
