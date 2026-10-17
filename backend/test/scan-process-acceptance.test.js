import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
// Real local Node fixture processes; no scanner, container engine, target or model.
await mock.module('../src/tools/containerEngine.js',{namedExports:{getEngine:async()=> 'host'}});
const {runTool}=await import('../src/tools/toolRunner.js');

test('acceptance: actual fixture process preserves output on nonzero exit',async()=>{
 const result=await runTool(process.execPath,['-e',"process.stdout.write('fixture discovery\\n');process.exitCode=7"],{timeout:2000});
 assert.equal(result.exitCode,7);assert.equal(result.success,false);
 assert.equal(result.stdout,'fixture discovery');assert.equal(result.processStopped,true);
});

test('acceptance: actual fixture process timeout and cancellation retain output and confirm stop',async t=>{
 for(const mode of ['timeout','abort']) await t.test(mode,async()=>{
  const controller=new AbortController();
  const result=await runTool(process.execPath,['-e',"process.stdout.write('fixture ready\\n');setInterval(()=>{},1000)"],{
   timeout:500,signal:controller.signal,onOutput:()=>{if(mode==='abort')controller.abort();}
  });
  assert.equal(result.success,false);assert.match(result.stdout,/fixture ready/);
  assert.equal(result.processStopped,true);
  assert.equal(mode==='timeout'?result.timedOut:result.aborted,true);
 });
});

test('acceptance: actual split UTF8 output remains readable as stored evidence',async()=>{
 const code="const b=Buffer.from('中文 fixture');process.stdout.write(b.subarray(0,1));setTimeout(()=>process.stdout.write(b.subarray(1)),40)";
 const result=await runTool(process.execPath,['-e',code],{timeout:2000});
 assert.equal(result.success,true);assert.equal(result.stdout,'中文 fixture');
});
