import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {captureCscanSource} from '../src/services/cscanSourceEvidence.js';
import {collectCscanReport} from '../src/services/cscanReportCollector.js';
import {parseCompletedCscanReport,parseNativeReport} from '../src/services/cscanNative.js';

test('source copies contain actual bytes only from the current Flow, excluding links and other artifacts',async t=>{
  const root=await mkdtemp(join(tmpdir(),'cscan-evidence-'));t.after(()=>rm(root,{recursive:true,force:true}));
  await mkdir(join(root,'flow-12/src/nested'),{recursive:true});
  await mkdir(join(root,'flow-13/src'),{recursive:true});
  await writeFile(join(root,'flow-12/src/nested/main.c'),'int main() { return 0; }\n');
  await writeFile(join(root,'flow-13/src/other.c'),'other target');
  await writeFile(join(root,'flow-12/src/.env'),'not source');
  await symlink(join(root,'flow-13/src/other.c'),join(root,'flow-12/src/escape.c'));
  const result=await captureCscanSource({workDir:root},'12');
  assert.equal(result.files.length,1);assert.equal(result.files[0].path,'/work/src/nested/main.c');
  assert.equal(result.files[0].content,'int main() { return 0; }\n');assert.equal(result.files[0].sha256.length,64);
  assert.equal(await captureCscanSource({workDir:root},'../13'),null);
});

test('final report deadline also bounds a model that ignores cancellation',async()=>{
  await assert.rejects(parseCompletedCscanReport('input.c contains a finding','/src',{timeoutMs:15,llm:()=>new Promise(()=>{})}),/超时/);
});

test('report model receives its independent long timeout',async()=>{
  await parseNativeReport('input.c contains a finding','/src',{modelTimeoutMs:900000,llm:async(_,options)=>{
    assert.equal(options.timeoutMs,900000);return {ok:true,content:'{"findings":[]}'};
  }});
});

test('report Assistant polls one request and rejects invented excerpts without duplicate mutations',async()=>{
  for(const invented of [false,true]) {
    let creates=0,polls=0;const saved=[];
    const client={createAssistant:async()=>{creates++;assert.equal(saved[0].state,'dispatching');return {id:'a'};},
      assistants:async()=>[{id:'a',useAgents:false,status:++polls<3?'running':'waiting'}],
      assistantLogs:async()=>[{id:'1',type:'assistant',message:JSON.stringify({reports:[{source_type:'task',source_id:'t',text:invented?'invented':'original evidence'}]})}],
      evidence:async()=>({tasks:[{id:'t',result:'original evidence',subtasks:[]}],terminalLogs:[],messageLogs:[]})};
    const result=await collectCscanReport(client,'12',{pollMs:1,onRawReport:async row=>saved.push(row)});
    assert.equal(creates,1);assert.equal(polls,3);assert.equal(result.state,invented?'uncertain':'complete');
    assert.ok(saved.some(row=>row.state==='received'));
    assert.ok(saved.at(-1).report.includes(invented?'invented':'original evidence'),'failed validation retains the original Assistant response');
    if(!invented)assert.equal(result.markdown,'original evidence');
  }
});
