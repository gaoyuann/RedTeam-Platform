import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
let current;
await mock.module('child_process',{namedExports:{execFile:()=>{throw new Error('unexpected external command');},spawn:()=>{
 const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();
 child.kill=()=>{queueMicrotask(()=>child.emit('close',-1));return true;};current=child;return child;
}}});
await mock.module('../src/tools/containerEngine.js',{namedExports:{getEngine:async()=> 'host'}});
const {runTool}=await import('../src/tools/toolRunner.js');

test('runner passes full chunks before evidence cap, preserving nonzero/timeout/abort output',async t=>{
 for(const mode of ['nonzero','timeout','abort','limit']) await t.test(mode,async()=>{
  const controller=new AbortController();const chunks=[];
  const promise=runTool('nmap',[],{timeout:mode==='timeout'?10:1000,maxOutputKB:1,signal:controller.signal,
    onOutput:(data,channel)=>chunks.push([data.toString(),channel])});
  await new Promise(r=>setImmediate(r));
  const output='recognized fixture output\n'+(mode==='limit'?'x'.repeat(1500):'');
  current.stdout.emit('data',Buffer.from(output));
  if(mode==='abort') controller.abort();
  if(mode==='nonzero') current.emit('close',1);
  const result=await promise;
  assert.equal(result.success,false);
  assert.ok(result.stdout.startsWith('recognized fixture output'));
  assert.equal(chunks[0][0],output);
  assert.equal(result.outputBytes,Buffer.byteLength(output));
  assert.equal(result.processStopped,true);
  const count=chunks.length; current.stdout.emit('data',Buffer.from('late fixture')); current.emit('close',0);
  assert.equal(chunks.length,count,'late callback cannot collect or settle again');
  if(mode==='limit') {assert.equal(result.outputLimitExceeded,true);assert.ok(Buffer.byteLength(result.stdout)<=1024);}
  if(mode==='timeout') assert.equal(result.timedOut,true);
  if(mode==='abort') assert.equal(result.aborted,true);
 });
});
