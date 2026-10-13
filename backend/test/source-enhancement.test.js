import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {sourceAnalysisOptions,sourceToolArgs} from '../src/services/sourceScanPolicy.js';
import {createSourceSnapshot} from '../src/services/sourceSnapshot.js';
import {prepareSourceCompilation,hostCompilationUnits} from '../src/services/sourceCompilation.js';
import {normalizeSourceFinding,normalizeSourceAssessment} from '../src/services/sourceScanFindings.js';
import {counterReviewSources} from '../src/services/sourceCounterReview.js';
import {createSourceContextIndex} from '../src/services/sourceContext.js';
import {sourceRuntimeMapping} from '../src/services/sourceRuntimeMapping.js';
import {normalizeEvidenceCriteria,evaluateEvidenceCriteria} from '../src/services/sourceEvidenceCriteria.js';
import {parseSourceDiagnostics} from '../src/services/sourceDiagnostics.js';
import {scoreSourceBenchmark} from '../src/services/sourceBenchmark.js';
import {runTool} from '../src/tools/toolRunner.js';
import {parseCppcheck} from '../src/services/sourceToolParsers.js';
import http from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';

const doc={path:'main.c',content:'void copy(char *input) {\n char buffer[4]; strcpy(buffer,input);\n}',start_line:1,end_line:3,sha256:'frozen'};
const cite={file:'main.c',start_line:2,end_line:2,role:'sink',note:'Fixed buffer copy'};
const assessment={verdict:'candidate',input_control:'unknown',reachability:'unknown',guard:'ineffective',reason:'Unchecked copy, caller unknown',
  missing_conditions:['Need caller and runtime entry'],citations:[cite],counter_evidence:[]};

test('structured assessments ground positive and negative conclusions, retaining legacy findings',()=>{
  const old=normalizeSourceFinding({file:'main.c',start_line:2,title:'copy',reason:'tool warning'},[doc]);
  assert.equal(old.assessment.guard,'unknown');assert.equal(old.runtime_verified,false);
  assert.equal(normalizeSourceAssessment(assessment,[doc]).citations[0].code,' char buffer[4]; strcpy(buffer,input);');
  assert.throws(()=>normalizeSourceAssessment({...assessment,citations:[{...cite,file:'invented.c'}]},[doc]),/未读取/);
  assert.throws(()=>normalizeSourceAssessment({...assessment,verdict:'unlikely'},[doc]),/反证/);
  assert.throws(()=>normalizeSourceAssessment({...assessment,missing_conditions:[]},[doc]),/未知/);
  assert.throws(()=>normalizeSourceAssessment({...assessment,citations:[]},[doc]),/肯定/);
  const guarded={path:'safe.c',content:'if (length >= capacity) return;\nmemcpy(buffer,input,length+1);',start_line:1,end_line:2,sha256:'safe'};
  const refuted=normalizeSourceAssessment({...assessment,verdict:'unlikely',guard:'effective',citations:[],
    counter_evidence:[{file:'safe.c',start_line:1,role:'guard',note:'Length check rejects oversized input'}]},[guarded]);
  assert.equal(refuted.counter_evidence[0].source_sha256,'safe');
});

test('independent counter review is bounded, does not mutate original alerts and rejects fabricated evidence',async()=>{
  const entries=Array.from({length:12},(_,i)=>({id:i+1,data:{...normalizeSourceFinding({file:'main.c',start_line:2,title:'copy',reason:'warning',severity:'high'},[doc]),tools:['cppcheck']}}));
  const index=createSourceContextIndex([doc]);let calls=0;
  const result=await counterReviewSources(entries,[doc],index,{llm:async messages=>{
    calls++;const payload=JSON.parse(messages[1].content);assert.equal(payload.candidates.length,6);
    return {ok:true,content:JSON.stringify({reviews:payload.candidates.map(item=>({finding_id:item.finding_id,assessment}))})};
  }});
  assert.equal(calls,1);assert.equal(result.reviewed.length,6);assert.equal(entries[0].data.counter_review,undefined);
  assert.equal(result.eligible,12);assert.equal(result.omitted,6);
  const invalid=await counterReviewSources(entries,[doc],index,{llm:async()=>({ok:true,content:JSON.stringify({reviews:entries.slice(0,6).map(entry=>({finding_id:entry.id,
    assessment:{...assessment,citations:[{...cite,start_line:99,end_line:99}]}}))})})});
  assert.equal(invalid.reviewed.length,0);assert.ok(invalid.errors.length);
  const failed=await counterReviewSources(entries,[doc],index,{llm:async()=>{throw new Error('disconnected');}});
  assert.deepEqual(failed.errors,['disconnected']);
  const cancelled=new AbortController();cancelled.abort();
  await assert.rejects(counterReviewSources(entries,[doc],index,{signal:cancelled.signal,llm:async()=>({ok:true,content:'{}'})}),/取消/);
});

test('compile database limits flags and paths, retains unlisted units and never runs commands',()=>{
  const files=[{path:'main.c',content:doc.content},{path:'other.c',content:'int other;'},{path:'include/guard.h',content:'#define GUARD 1'}];
  const compilation={content:JSON.stringify([
    {directory:'/project',file:'main.c',arguments:['cc','-Iinclude','-I/elsewhere','-DGUARD=1','-std=c11','-fplugin=evil','@secrets','-o','-DFAKE=1','-c','main.c']},
    {directory:'/outside',file:'secret.c',arguments:['cc','-c','secret.c']},
    {directory:17,file:'main.c',arguments:['cc','-c','main.c']},
    {directory:'/project',file:'main.c',arguments:[]},
    {directory:'/project',file:'main.c',command:"cc -D'BAD=$(touch x)' -I'include' -c main.c"}
  ])};
  const connection={source_root:'/project',analysis:sourceAnalysisOptions({compile_database:'build/compile_commands.json'})};
  const result=prepareSourceCompilation({files,compilation},connection);
  assert.equal(result.summary.configured_units,2);assert.equal(result.summary.fallback_units,1);
  assert.equal(result.summary.external_paths,1);assert.equal(result.summary.skipped_units,3);
  const text=JSON.stringify(result.units);assert.ok(text.includes('-DGUARD=1'));
  for(const denied of ['elsewhere','fplugin','secrets','touch','FAKE']) assert.ok(!text.includes(denied),denied);
  assert.ok(sourceToolArgs('cppcheck',connection.analysis,result.summary).includes('--project=/src/project/.rt-compile-commands.json'));
  assert.ok(!JSON.stringify(hostCompilationUnits(result.units,'/snapshot')).includes('/src/project'));
  for(const path of ['../compile_commands.json','/compile_commands.json','build/../../compile_commands.json']) assert.throws(()=>sourceAnalysisOptions({compile_database:path}));
});

test('explicit compilation database outside normal walk is frozen; missing database keeps ordinary scanning',async t=>{
  const directory=await mkdtemp(join(tmpdir(),'rt-compilation-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const source=join(directory,'source');await mkdir(join(source,'build'),{recursive:true});await writeFile(join(source,'main.c'),doc.content);
  await writeFile(join(source,'build','compile_commands.json'),JSON.stringify([{directory:source,file:'main.c',arguments:['cc','-DENABLED=1','-c','main.c']}]));
  const connection={id:'compile',kind:'local',source_root:source,analysis:sourceAnalysisOptions({compile_database:'build/compile_commands.json'})};
  const snapshot=await createSourceSnapshot(connection,{snapshotRoot:join(directory,'snapshots')});
  assert.equal(snapshot.compilation.available,true);assert.equal(snapshot.documents.length,1);
  const database=JSON.parse(await readFile(join(snapshot.sourceDir,'.rt-compile-commands.json'),'utf8'));
  assert.ok(database[0].arguments.includes('-DENABLED=1'));assert.ok(!JSON.stringify(snapshot.compilation).includes(directory));
  const missing=await createSourceSnapshot({...connection,analysis:sourceAnalysisOptions({compile_database:'missing/compile_commands.json'})},{snapshotRoot:join(directory,'snapshots')});
  assert.equal(missing.compilation.available,false);assert.ok(missing.compilation.errors.length);
});

test('real cppcheck honors frozen compile macros and project includes', {skip:process.env.SOURCE_TEST_SAST!=='1'},async t=>{
  const directory=await mkdtemp(join(tmpdir(),'rt-build-context-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const source=join(directory,'source');await mkdir(join(source,'include'),{recursive:true});
  await writeFile(join(source,'include','guard.h'),'#define LIMIT 2\n');
  await writeFile(join(source,'main.c'),'#include "guard.h"\nint f(void) {\n#if ENABLED\n int b[LIMIT]; b[9]=1; return b[9];\n#else\n return 0;\n#endif\n}\n');
  const connection={id:'context',kind:'local',source_root:source,analysis:sourceAnalysisOptions({compile_database:'compile_commands.json'})};
  for(const enabled of [0,1]) {
    await writeFile(join(source,'compile_commands.json'),JSON.stringify([{directory:source,file:'main.c',arguments:['cc','-Iinclude','-DENABLED='+enabled,'-c','main.c']}]));
    const snapshot=await createSourceSnapshot(connection,{snapshotRoot:join(directory,'snapshots')});
    assert.equal(snapshot.documents.length,2);
    const result=await runTool('cppcheck',sourceToolArgs('cppcheck',connection.analysis,snapshot.compilation),{sourceDir:snapshot.sourceDir,timeout:60000});
    assert.equal(result.success,true,result.stderr);
    const defects=parseCppcheck(result.stdout+'\n'+result.stderr).filter(row=>row.result_data.rule==='arrayIndexOutOfBounds');
    assert.equal(defects.length>0,enabled===1,result.stderr);
  }
});

test('runtime mapping separates source route candidates from proven call paths and TCP input',()=>{
  const finding={file:'route.c',start_line:5,code:'if (strcmp(request.uri,"/copy") == 0) copy(input);',trace:[]};
  const target='http://127.0.0.1:8090/';
  const mapping=sourceRuntimeMapping(finding,{url:target,connected:true},target);
  assert.equal(mapping.status,'candidate');assert.equal(mapping.entries[0].url,target+'copy');
  assert.equal(mapping.semantic_link_verified,false);assert.equal(mapping.entries[0].observed,false);
  assert.equal(sourceRuntimeMapping(finding,{},null).entries.length,0);
  assert.equal(sourceRuntimeMapping(finding,{connected:true},'tcp://127.0.0.1:8091').status,'unresolved');
});

test('observable criteria distinguish failed, matched, unmatched and unsupported comparisons',()=>{
  const criterion=normalizeEvidenceCriteria({kind:'response_contains',value:'boundary',limitations:'Not proof of memory corruption'});
  const result={success:true,stdout:JSON.stringify({url:'http://host/check',connected:true,response:'boundary',status_code:200})};
  assert.equal(evaluateEvidenceCriteria(criterion,result).status,'matched');
  assert.equal(evaluateEvidenceCriteria({...criterion,value:'absent'},result).status,'not_matched');
  assert.equal(evaluateEvidenceCriteria(criterion,{...result,success:false}).status,'inconclusive');
  const difference=normalizeEvidenceCriteria({kind:'response_differs',limitations:'Responses may vary independently'});
  assert.equal(evaluateEvidenceCriteria(difference,result,{url:'http://host/check',connected:true,response:'normal'}).status,'matched');
  assert.equal(evaluateEvidenceCriteria(difference,result,{url:'http://host/other',connected:true,response:'normal'}).status,'inconclusive');
  assert.equal(evaluateEvidenceCriteria(difference,result,{url:'http://host/check',connected:true,response:'normal',success:false}).status,'inconclusive');
  assert.equal(evaluateEvidenceCriteria(difference,result,{url:'http://host/check',method:'POST',connected:true,response:'normal'}).status,'inconclusive');
  assert.equal(evaluateEvidenceCriteria(difference,result).runtime_verified,false);
  assert.throws(()=>normalizeEvidenceCriteria({kind:'shell',limitations:'x'}));
});

test('diagnostic parsing retains observed reports and only maps unique real source locations',()=>{
  const text='ERROR: AddressSanitizer: heap-use-after-free\n#0 f /snapshot/main.c:2:1\n#1 other /secret/not-read.c:8\n';
  const reports=parseSourceDiagnostics(text,[doc]);assert.equal(reports[0].type,'heap-use-after-free');
  assert.deepEqual(reports[0].locations,[{file:'main.c',line:2,source_sha256:'frozen'}]);assert.equal(reports[0].runtime_verified,false);
  assert.equal(parseSourceDiagnostics('/snapshot/main.c:2:3: runtime error: load of null pointer of type int',[doc])[0].type,'null-pointer');
  assert.equal(parseSourceDiagnostics('AddressSanitizer is enabled',[doc]).length,0);
  const combined=parseSourceDiagnostics(text+'ERROR: AddressSanitizer: stack-buffer-overflow\n#0 f /snapshot/main.c:3:1\n',[doc]);
  assert.equal(combined[0].locations.length,1);assert.equal(combined[1].locations[0].line,3);
  assert.equal(parseSourceDiagnostics(text,[doc,{...doc,path:'other/main.c'}])[0].locations.length,1);
  assert.equal(parseSourceDiagnostics(text,[doc,{...doc}])[0].locations.length,1);
  const wrapped=parseSourceDiagnostics(JSON.stringify({stdout:'normal output',stderr:text,runtime_verified:true,locations:[{file:'invented.c',line:9}]}),[doc]);
  assert.deepEqual(wrapped,reports,'JSON stderr keeps actual lines and ignores endpoint verdicts/locations');
  assert.equal(parseSourceDiagnostics(JSON.stringify({stdout:'a'.repeat(65536),stderr:text}),[doc]).length,0,'oversized envelopes cannot bypass the output limit');
});

test('benchmark metrics report missed defects and fixed-version warnings separately',()=>{
  const cases=[{file:'bad.c',line:5,vulnerable:true},{file:'missed.c',line:5,vulnerable:true},{file:'fixed.c',line:2,vulnerable:false}];
  const score=scoreSourceBenchmark([{file:'bad.c',line:5},{file:'fixed.c',line:2}],cases);
  assert.equal(score.true_positive,1);assert.equal(score.false_negative,1);assert.equal(score.false_positive,1);
  assert.equal(score.precision,0.5);assert.equal(score.recall,0.5);
  assert.equal(scoreSourceBenchmark([],cases).precision,null);
  assert.equal(scoreSourceBenchmark([{file:'bad.c',line:5,cwe:'CWE-999'}],[{file:'bad.c',line:5,vulnerable:true,cwe:'CWE-120'}]).false_negative,1);
});

test('benchmark AI option evaluates actual frozen tools with bounded model protocol and isolated database',
  {skip:process.env.SOURCE_TEST_SAST!=='1'},async t=>{
  const directory=await mkdtemp(join(tmpdir(),'rt-model-benchmark-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  let modelCalls=0;
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req) body+=chunk;
    const messages=JSON.parse(body).messages,payload=JSON.parse(messages[1].content);modelCalls++;
    let result;
    if(messages[0].content.includes('独立的源码反证复核员')) result={reviews:payload.candidates.map(item=>({finding_id:item.finding_id,
      assessment:{...assessment,reason:'Fixture review remains subject to runtime linkage',citations:[{...cite,file:item.finding.file,start_line:item.finding.start_line,end_line:item.finding.start_line}]}}))};
    else {
      const file=payload.document.file,lines={'vulnerable/bounds.c':4,'vulnerable/null.c':3,'vulnerable/lifetime.cpp':4};
      result={findings:lines[file] ? [{file,start_line:lines[file],title:'Controlled fixture candidate',reason:'Known fixture diagnostic site',severity:'high',
        cwe:({'vulnerable/bounds.c':'CWE-120','vulnerable/null.c':'CWE-476','vulnerable/lifetime.cpp':'CWE-416'})[file],
        assessment:{...assessment,citations:[{...cite,file,start_line:lines[file],end_line:lines[file]}]}}] : []};
    }
    res.setHeader('content-type','application/json');res.end(JSON.stringify({choices:[{message:{content:JSON.stringify(result)}}]}));
  });
  server.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const output=join(directory,'report.json');
  await promisify(execFile)(process.execPath,[fileURLToPath(new URL('../scripts/source-benchmark.js',import.meta.url)),'--ai','--output',output],
    {timeout:30000,maxBuffer:2*1024*1024,env:{...process.env,LLM_API_KEY:'fixture',LLM_BASE_URL:'http://127.0.0.1:'+server.address().port,LLM_MODEL:'fixture'}});
  const report=JSON.parse(await readFile(output,'utf8'));
  assert.equal(report.ai_evaluated,true);assert.equal(report.ai.primary.true_positive,3);assert.equal(report.ai.primary.false_positive,0);
  assert.ok(report.ai.coverage.ai_counter_review.reviewed>0);assert.equal(report.ai.coverage.ai_model_calls,modelCalls);
  assert.equal(report.errors.length,0);
});
