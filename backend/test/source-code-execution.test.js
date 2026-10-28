import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import http from 'node:http';
import express from 'express';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {runSourceCode as productionRunner,codeContainerArgs} from '../src/tools/sourceCodeRunner.js';
import {normalizeCodeArtifact,codeHash,parseCodeInvocation,codeImage} from '../src/services/verificationCodeArtifact.js';

const runner=fileURLToPath(new URL('../src/tools/sourceCodeWorker.py',import.meta.url));
function fixtureRun(input,{missingCompiler=false}={}) {
  // Only these fixed, reviewed fixture programs run on the test host. Production
  // always uses the isolated container; the transport is replaced in this test.
  return new Promise((resolve,reject)=>{
    const args=missingCompiler?['-I','-B','-c','import runpy, shutil, sys; shutil.which=lambda *a, **kw: None; runpy.run_path(sys.argv[1], run_name="__main__")',runner]:['-I','-B',runner];
    const child=execFile('python3',args,{timeout:45000,maxBuffer:512*1024},(error,stdout,stderr)=>error?reject(error):resolve({stdout,stderr}));
    child.stdin.end(input);
  });
}
const source="import sys\nprint('fixture-local-marker' if sys.argv[1] == 'probe' else 'normal fixture')";
const execution={language:'python',entrypoint:'repro.py',baseline:{args:['normal'],stdin:''},probe:{args:['probe'],stdin:''},expected_output:'fixture-local-marker'};
const answer={state:'ready',missing_information:[],files:[{filename:'repro.py',language:'python',source}],execution,dependencies:[],run_conditions:['Isolated local fixture'],expected_results:['Different fixture marker'],failure_reasons:['Missing runtime'],remediation:['Validate input'],model_inferences:['Local model of a branch']};

test('saved generated code -> frozen plan -> platform executor -> actual fixture runs -> linked local-only result',async t=>{
  let engine='docker',available=true,calls=0;
  const phases=[];
  const resources=await import('../src/services/resourceInspection.js');
  mock.module('../src/tools/containerEngine.js',{namedExports:{getEngine:async()=>engine}});
  mock.module('../src/services/resourceInspection.js',{namedExports:{...resources,inspectRuntimeResources:async options=>{
    assert.equal(options.imageMap['source-code-runner'],'rt-web','Python preflight reuses the existing web image');
    return {passed:available,missing:available?[]:['fixture image missing']};
  }}});
  mock.module('../src/tools/sourceCodeRunner.js',{namedExports:{runSourceCode:async(args,options)=>productionRunner(args,options,{
    getEngine:async()=>engine,
    runContainer:async(binary,args,input)=>{
      assert.equal(binary,'docker');assert.ok(args.includes('--read-only'));assert.ok(args.includes('none'));assert.ok(!args.includes('-v'));
      const value=JSON.parse(input);assert.equal(value.files[0].source,source);phases.push(value.phase);
      assert.ok(args.includes('rt-web'));assert.ok(args.includes('--entrypoint'));
      assert.equal(args.at(-2),'-c');assert.ok(args.at(-1).includes('def main():'));
      const result=await fixtureRun(input),obs=JSON.parse(result.stdout);
      return {success:obs.complete,exitCode:obs.complete?0:1,stdout:result.stdout,stderr:result.stderr,executionMode:'docker',toolStarted:true,artifactConsumed:true,processStopped:true};
    }
  })}});
  const {getDb,closeDb}=await import('../src/db/connection.js');
  const {runMigrations}=await import('../src/db/migrate.js');
  const {default:routes}=await import('../src/routes/findingVerifications.js');
  const {evaluateCodeRule}=await import('../src/services/sourceCodeRule.js');
  const db=getDb(':memory:');t.after(()=>{closeDb();mock.restoreAll();});
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('native_alice','fixture','user',1),('native_bob','fixture','user',1)").run();
  const target='http://fixture.invalid/source/';
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES('np',?,'completed','native_alice','ns','{}')").run(target);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id,parameters) VALUES('ns',?,'source_scan','COMPLETED','native_alice','np','{}')").run(target);
  const finding=JSON.stringify({title:'Local fixture branch',file:'fixture.c',start_line:1,reason:'A fixture branch for comparison',evidence_origin:'cscan_report'});
  const findingId=Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES('ns','source_finding',?,'high','cscan')").run(finding).lastInsertRowid);
  let actor='native_alice';
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:actor,role:'user'};next();});
  app.use('/tasks/:id/verifications',routes(db,{llm:async()=>{calls++;return {ok:true,content:JSON.stringify(answer)};}}));
  app.use((e,req,res,next)=>res.status(e.status || 500).json({error:e.message}));
  const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
  const base='http://127.0.0.1:'+server.address().port+'/tasks/np/verifications';
  const request=async(path,body,status=200)=>{
    const response=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    const json=await response.json();assert.equal(response.status,status,JSON.stringify(json));return json.data;
  };
  const item=await request('',{finding_id:findingId}),path='/'+item.id;
  const generated=await request(path+'/verification-code',{expected_revision:0,request_id:'native_fixture_01',automatic_context:true,authorization_confirmed:true});
  assert.equal(generated.state,'ready');assert.deepEqual(phases,[]);
  assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
  await request(path+'/code-plan',{expected_revision:0,artifact_id:'vc_outside'},422);
  actor='native_bob';await request(path+'/code-plan',{expected_revision:0,artifact_id:generated.id},403);actor='native_alice';
  await request(path+'/code-plan',{expected_revision:0,artifact_id:generated.id});
  assert.equal(calls,1,'preparation uses saved code, never asks a model to rewrite it');assert.deepEqual(phases,[]);
  let detail=await request(path),plan=detail.plans[0];
  assert.equal(detail.readiness.ready,true,JSON.stringify(detail.readiness));
  assert.equal(plan.content.code_payload.id,generated.id);
  assert.equal(plan.content.verification_contract.object.execution_mode,'local_simulation');
  const start=async(key)=>{
    const body={revision:1,fingerprint:plan.fingerprint,confirmed:true,request_id:key};
    const attempt=await request(path+'/start',body);
    assert.equal((await request(path+'/start',body)).id,attempt.id);
    for(let i=0;i<1000;i++) {detail=await request(path);if(detail.attempts[0] && !['queued','running','cancelling'].includes(detail.attempts[0].state))return detail.attempts[0];await new Promise(r=>setTimeout(r,10));}
    assert.fail('fixture run did not finish: '+JSON.stringify(detail.attempts[0]));
  };
  const attempt=await start('native_run_01');
  assert.equal(attempt.state,'completed',JSON.stringify(attempt));
  assert.deepEqual(phases,['baseline','probe']);assert.equal(attempt.evidence.length,2);
  assert.equal(attempt.summary.result.status,'achieved',JSON.stringify(attempt.summary));
  assert.equal(attempt.summary.conclusion,'inconclusive','local simulation must not confirm a real-target vulnerability');
  assert.ok(attempt.evidence.every(e=>e.observation.mode==='local_simulation' && e.evidence_data.finding_verification.artifact_consumed));
  const content=JSON.parse(db.prepare('SELECT content FROM finding_verification_plans WHERE verification_id=?').get(item.id).content);
  const evidence=db.prepare('SELECT * FROM evidence_records WHERE run_id=? ORDER BY step_index').all(attempt.run_id);
  const linked={...attempt,fingerprint:plan.fingerprint},rule=content.assessment_rule,checked={...content,finding_id:findingId};
  assert.equal(evaluateCodeRule(rule,evidence,linked,checked).conclusion,'confirmed');
  for(const mutation of [o=>{o.complete=false;},o=>{o.artifact_hash='wrong';},o=>{o.run.timed_out=true;},o=>{o.run.truncated=true;},o=>{o.compile.ok=false;}]) {
    const altered=structuredClone(evidence),o=JSON.parse(altered[1].raw_stdout);mutation(o);altered[1].raw_stdout=JSON.stringify(o);
    assert.equal(evaluateCodeRule(rule,altered,linked,checked).conclusion,'inconclusive');
  }
  const negative=structuredClone(evidence),o=JSON.parse(negative[1].raw_stdout);o.run.stdout='normal fixture';negative[1].raw_stdout=JSON.stringify(o);
  assert.equal(evaluateCodeRule(rule,negative,linked,checked).conclusion,'not_verified');
  o.run.exit_code=1;negative[1].raw_stdout=JSON.stringify(o);assert.equal(evaluateCodeRule(rule,negative,linked,checked).conclusion,'inconclusive');
  const wrong=structuredClone(evidence),link=JSON.parse(wrong[1].evidence_data);link.finding_verification.artifact_consumed=false;wrong[1].evidence_data=JSON.stringify(link);
  assert.equal(evaluateCodeRule(rule,wrong,linked,checked).conclusion,'inconclusive');
  available=false;const missing=await start('native_image_missing');assert.equal(missing.state,'failed');assert.equal(missing.summary.result.status,'not_performed');assert.deepEqual(phases,['baseline','probe']);available=true;
  engine='host';const host=await start('native_host_blocked');assert.equal(host.state,'failed');assert.equal(host.summary.result.status,'not_performed');engine='docker';
  await request(path+'/start',{revision:1,fingerprint:plan.fingerprint,confirmed:true,request_id:'native_limit_04'},409);
  const saved=db.prepare('SELECT result FROM finding_verification_code WHERE id=?').get(generated.id).result;
  const changed=JSON.parse(saved);changed.files[0].source+='\n# changed';db.prepare('UPDATE finding_verification_code SET result=? WHERE id=?').run(JSON.stringify(changed),generated.id);
  assert.ok((await request(path)).readiness.reasons.some(r=>r.includes('载荷内容已变化')));
  db.prepare('UPDATE finding_verification_code SET result=? WHERE id=?').run(saved,generated.id);
  db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({...JSON.parse(finding),reason:'changed evidence'}),findingId);
  assert.ok((await request(path)).readiness.reasons.some(r=>r.includes('源码发现已变化')));
  await request(path+'/code-plan',{expected_revision:1,artifact_id:generated.id},422);
  assert.equal((await request(path)).attempts.length,3);assert.deepEqual(db.pragma('foreign_key_check'),[]);
});

test('artifact invocation rejects unsupported inputs; dedicated runner has no host fallback or arbitrary inline source',async()=>{
  const normalized=normalizeCodeArtifact(answer),artifact={id:'vc_fixture',hash:codeHash(normalized),...normalized};
  const args=[JSON.stringify({artifact_id:artifact.id,artifact_hash:artifact.hash,phase:'probe'})];
  assert.throws(()=>parseCodeInvocation([JSON.stringify({...JSON.parse(args[0]),source:'inline code'})]),/载荷引用/);
  assert.throws(()=>normalizeCodeArtifact({...answer,execution:{...execution,entrypoint:'../repro.py'}}),/入口/);
  assert.throws(()=>normalizeCodeArtifact({...answer,execution:{...execution,probe:execution.baseline}}),/必须不同/);
  assert.throws(()=>normalizeCodeArtifact({...answer,execution:{...execution,diagnostics:'asan_ubsan'}}),/诊断模式/);
  let called=0;
  assert.equal((await productionRunner(args,{},{})).toolStarted,false);
  const blocked=await productionRunner(args,{codeArtifact:artifact},{getEngine:async()=> 'host',runContainer:()=>{called++;}});
  assert.equal(blocked.executionMode,'blocked');assert.equal(called,0);
  const controller=new AbortController();controller.abort();
  assert.equal((await productionRunner(args,{codeArtifact:artifact,signal:controller.signal},{getEngine:()=>{called++;}})).aborted,true);assert.equal(called,0);
});

test('language routing reuses existing images and keeps legacy artifact hashes stable',()=>{
  for(const [language,image] of [['python','rt-web'],['c','rt-sast-c'],['cpp','rt-sast-c']]) {
    assert.equal(codeImage(language),image);
    const args=codeContainerArgs('rt-code-fixture',language);
    assert.ok(args.includes(image));assert.equal(args[args.indexOf('--entrypoint')+1],'python3');
    assert.equal(args.at(-2),'-c');assert.ok(args.at(-1).includes('def main():'));
  }
  assert.throws(()=>codeImage('unsupported'),/不支持/);
  const legacy=normalizeCodeArtifact(answer);
  assert.equal(Object.hasOwn(legacy.execution,'diagnostics'),false,'old manifest normalization must not insert a field and change its hash');
  assert.equal(codeHash(legacy),codeHash({mode:'local_simulation',files:answer.files,execution:answer.execution}));
});

test('fixed container entrypoint runs reviewed Python/C/C++ fixtures and retains compilation failures',async()=>{
  const programs={python:source,c:'#include <stdio.h>\n#include <string.h>\nint main(int n,char **v){puts(n>1 && strcmp(v[1],"probe")==0?"fixture-local-marker":"normal fixture");return 0;}\n',
    cpp:'#include <iostream>\n#include <string>\nint main(int n,char **v){std::cout<<(n>1 && std::string(v[1])=="probe"?"fixture-local-marker":"normal fixture");}\n'};
  for(const [language,program] of Object.entries(programs)) {
    const filename='repro.'+({python:'py',c:'c',cpp:'cpp'}[language]);
    const artifact=normalizeCodeArtifact({...answer,files:[{filename,language,source:program}],execution:{...execution,language,entrypoint:filename,diagnostics:'none'}});
    for(const phase of ['baseline','probe']) {
      const result=JSON.parse((await fixtureRun(JSON.stringify({...artifact,artifact_id:'vc_fixture',artifact_hash:codeHash(artifact),phase}))).stdout);
      assert.equal(result.compile.ok,true,JSON.stringify(result));assert.equal(result.complete,true,JSON.stringify(result));
      assert.equal(result.compile.diagnostics,'none');
      assert.equal(result.run.exit_code,0,JSON.stringify(result));assert.equal(result.run.stdout.includes('fixture-local-marker'),phase==='probe');
    }
  }
  const broken=normalizeCodeArtifact({...answer,files:[{filename:'repro.c',language:'c',source:'invalid C fixture'}],execution:{...execution,language:'c',entrypoint:'repro.c',diagnostics:'none'}});
  const result=JSON.parse((await fixtureRun(JSON.stringify({...broken,artifact_id:'vc_fixture',artifact_hash:codeHash(broken),phase:'probe'}))).stdout);
  assert.equal(result.compile.ok,false);assert.equal(result.run.started,false);assert.equal(result.complete,false);assert.ok(result.compile.stderr.length);
});

test('existing image missing a compiler yields explicit evidence without running code or changing diagnostics',async()=>{
  for(const language of ['c','cpp']) {
    const artifact=normalizeCodeArtifact({...answer,files:[{filename:'repro.'+language,language,source:'int main(void) { return 0; }'}],
      execution:{...execution,language,entrypoint:'repro.'+language}});
    const result=JSON.parse((await fixtureRun(JSON.stringify({...artifact,artifact_id:'vc_missing',artifact_hash:codeHash(artifact),phase:'probe'}),{missingCompiler:true})).stdout);
    assert.equal(result.compile.ok,false);assert.equal(result.compile.exit_code,127);
    assert.match(result.compile.stderr,new RegExp(language==='c'?'gcc':'g\\+\\+'));
    assert.equal(result.compile.diagnostics,'asan_ubsan','legacy sanitizer requirements must not be silently downgraded');
    assert.equal(result.run.started,false);assert.equal(result.complete,false);
  }
});

test('container lifecycle bounds timeout/output, forwards cancellation and requires actual removal confirmation',async()=>{
  const artifact={id:'vc_lifecycle',...normalizeCodeArtifact(answer)};artifact.hash=codeHash(normalizeCodeArtifact(artifact));
  const args=[JSON.stringify({artifact_id:artifact.id,artifact_hash:artifact.hash,phase:'probe'})];
  for(const mode of ['normal','cancel','timeout','output','stop-unconfirmed','invalid-output','spawn-error']) {
    const commands=[],controller=new AbortController();
    const fakeSpawn=(binary,argv)=>{
      assert.equal(binary,'docker');commands.push(argv);
      const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();child.pid=123;
      child.kill=()=>{queueMicrotask(()=>child.emit('close',-1));return true;};
      if(argv[0]==='run') {
        assert.equal(argv[argv.indexOf('--network')+1],'none');assert.ok(!argv.includes('--privileged'));
        assert.ok(!argv.includes('-v') && !argv.includes('--mount'));
        child.stdin.on('finish',()=>{
          if(mode==='cancel'){controller.abort();return;}
          if(mode==='timeout')return;
          if(mode==='spawn-error'){child.emit('error',new Error('fixture spawn failed'));return;}
          const observation={format:'local-code-observation-v1',mode:'local_simulation',artifact_id:artifact.id,artifact_hash:artifact.hash,phase:'probe',
            complete:true,compile:{ok:true},run:{started:true,stdout:'fixture-local-marker',stderr:'',exit_code:0}};
          child.stdout.emit('data',Buffer.from(mode==='output'?'x'.repeat(300000):mode==='invalid-output'?'invalid json':JSON.stringify(observation)));
          queueMicrotask(()=>child.emit('close',0));
        });
      } else if(argv[0]==='rm')queueMicrotask(()=>child.emit('close',1)); // absent is allowed only after successful listing
      else if(argv[0]==='ps')queueMicrotask(()=>child.emit('close',mode==='stop-unconfirmed'?1:0));
      else assert.fail('unexpected container command');
      return child;
    };
    const result=await productionRunner(args,{codeArtifact:artifact,signal:controller.signal,timeout:mode==='timeout'?5:1000},{getEngine:async()=> 'docker',spawn:fakeSpawn});
    assert.ok(commands.some(a=>a[0]==='rm') && commands.some(a=>a[0]==='ps'));
    assert.equal(result.processStopped,mode!=='stop-unconfirmed',mode);
    if(mode==='normal')assert.equal(result.success,true);
    if(mode==='stop-unconfirmed')assert.equal(result.processStopped,false,'CLI completion alone is not stop confirmation');
    if(mode==='cancel')assert.equal(result.aborted,true);
    if(mode==='timeout')assert.equal(result.timedOut,true);
    if(mode==='output')assert.equal(result.outputLimitExceeded,true);
    if(['invalid-output','spawn-error'].includes(mode))assert.equal(result.success,false);
  }
});
