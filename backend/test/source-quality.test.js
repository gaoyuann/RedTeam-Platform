import {cscanFixture} from './helpers/cscanFixture.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {sourceAnalysisOptions,sourceToolArgs,sourceReviewChunks} from '../src/services/sourceScanPolicy.js';
import {parseCppcheck,parseFlawfinder} from '../src/services/sourceToolParsers.js';
import {executeScan} from '../src/services/scanExecutor.js';

test('SAST parsers retain reordered XML attributes, entities and multiline CSV',()=>{
  const rows=parseCppcheck('<results><error cwe="120" msg="a &lt; b &amp; c" severity="error" id="bounds"><location column="3" line="9" file="/src/project/a&amp;b.c" info="input"/></error></results>');
  assert.equal(rows[0].result_data.line,9);
  assert.equal(rows[0].result_data.file,'/src/project/a&b.c');
  assert.equal(rows[0].result_data.message,'a < b & c');
  const csv='File,Line,Level,Name,Warning,CWEs,Suggestion,Context\n"/src/project/a.c",2,4,strcpy,"unchecked, copy",CWE-120,"check bounds","first\nsecond"\n';
  const flaws=parseFlawfinder(csv);
  assert.equal(flaws.length,1);
  assert.equal(flaws[0].result_data.context,'first\nsecond');
  assert.equal(flaws[0].result_data.suggestion,'check bounds');
});

test('bounded review prioritizes an alert deep in a file and rejects unsafe analysis settings',()=>{
  const lines=Array.from({length:900},()=>';'); lines[760]='strcpy(buffer, input);';
  const doc={path:'large.c',content:lines.join('\n'),start_line:1,end_line:900};
  const chunks=sourceReviewChunks([doc],[{file:'large.c',start_line:761}]);
  assert.ok(chunks[0].start_line<=761 && chunks[0].end_line>=761);
  assert.ok(chunks[0].start_line>600);
  assert.throws(()=>sourceAnalysisOptions({defines:['X;touch /tmp/x']}));
  assert.throws(()=>sourceAnalysisOptions({platform:'arm64;sh'}));
  assert.ok(sourceToolArgs('cppcheck',{standard:'c++17',defines:['FEATURE=1']}).includes('-DFEATURE=1'));
});

test('CScan executor imports report-backed C/C++ findings without inventing snapshots or source-version evidence',async t=>{
  const cscan=await cscanFixture(t,['bounds.c','null.c','lifetime.cpp'].map((name,index)=>({
    file:'vulnerable/'+name,start_line:[4,3,4][index],title:'Fixture '+name,reason:'Test-owned source candidate',severity:'high',
    trace:[{file:'vulnerable/'+name,start_line:1,role:'supporting',note:'Fixture context'},
      {file:'vulnerable/'+name,start_line:[4,3,4][index],role:'sink',note:'Fixture diagnostic site'}]})));
  const directory=await mkdtemp(join(tmpdir(),'rt-quality-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const db=getDb(':memory:');t.after(closeDb);
  const migrations=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for(const name of (await readdir(migrations)).sort()) {
    if(name.includes('import')) continue;
    const module=await import(migrations+name);(module.default || module.up)(db);
  }
  const previous=process.env.SOURCE_SCAN_CONNECTIONS_FILE;
  process.env.SOURCE_SCAN_CONNECTIONS_FILE=join(directory,'connections.json');
  t.after(()=>{if(previous===undefined) delete process.env.SOURCE_SCAN_CONNECTIONS_FILE; else process.env.SOURCE_SCAN_CONNECTIONS_FILE=previous;});
  await writeFile(process.env.SOURCE_SCAN_CONNECTIONS_FILE,JSON.stringify([{id:'quality',kind:'local',source_root:resolve('test/fixtures/source'),targets:['http://127.0.0.1:9/'],analysis:{platform:'unix64'}}]));
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,parameters) VALUES ('quality','http://127.0.0.1:9/','source_scan',?)").run(JSON.stringify({connection_id:'quality',ai_analysis:false}));
  const result=await executeScan('quality');
  assert.equal(result.status,'PARTIAL',JSON.stringify(result));
  const task=db.prepare("SELECT target_class FROM scan_tasks WHERE scan_task_id='quality'").get();
  assert.equal(task.target_class,'web_url');
  assert.equal(result.outcomes.find(item=>item.tool_id==='cscan').success,true);
  assert.equal(result.outcomes.some(item=>['cppcheck','flawfinder','source-ai'].includes(item.tool_id)),false);
  const findings=db.prepare("SELECT * FROM scan_results WHERE result_type='source_finding'").all().map(row=>JSON.parse(row.result_data));
  const cpp=findings.filter(item=>item.tools.includes('cscan'));
  for(const filename of ['bounds.c','null.c','lifetime.cpp']) assert.ok(cpp.some(item=>item.file==='vulnerable/'+filename),filename);
  assert.equal(cpp.filter(item=>item.file.startsWith('fixed/')).length,0);
  assert.ok(findings.every(item=>item.evidence_origin==='cscan_report' && item.code==='' && item.trace.length===0));
  assert.ok(findings.every(item=>item.source_sha256===null && item.snapshot_id===null && !item.runtime_verified && !item.source_version_verified));
  assert.deepEqual(await readdir(cscan.sources),[],'the executor must not populate a source mount');
  const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
  assert.equal(coverage.source_read,false);assert.equal(coverage.input_mode,'remote_agent');
  assert.equal(coverage.cscan_complete,true);assert.equal(coverage.engine,'cscan');
  const flowId=coverage.cscan.flow_id;
  assert.equal((await executeScan('quality')).ok,false);
  assert.equal(JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis).cscan.flow_id,flowId);
  // Corrected memcpy can still produce a lexical warning: do not pretend rules prove safety.
  assert.equal(cpp.length,3,'all three protocol fixture findings survive the production importer');
});
