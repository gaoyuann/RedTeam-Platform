import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
let engine='docker',calls=[],mode='success';
await mock.module('../src/tools/containerEngine.js',{namedExports:{getEngine:async()=>engine}});
await mock.module('child_process',{namedExports:{execFile:()=>assert.fail('unexpected execFile'),spawn:(bin,args,options)=>{
 const c=new EventEmitter();c.pid=31337;c.stdout=new EventEmitter();c.stderr=new EventEmitter();
 calls.push({bin,args,options});
 c.kill=()=>{queueMicrotask(()=>c.emit('close',null));return true;};
 queueMicrotask(()=>{
  if(args[0]==='rm'){c.emit('close',0);return;}
  if(mode==='wait')return;
  c.stdout.emit('data',Buffer.from('Parameter: id (GET)\n Type: boolean-based blind\n Title: fixture\n[*] ending @ 12:00'));
  c.emit('close',0);
 });return c;
}}});
const {runTool}=await import('../src/tools/toolRunner.js');
const {sqlDetectionArgs}=await import('../src/services/webSqlDetector.js');
test('real runner builds private host/docker/podman arguments without pulling or sharing runtime output',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'rt-runner-fixture-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 for(const current of ['docker','podman','host']){
  engine=current;calls=[];mode='success';
  const result=await runTool('sqlmap',sqlDetectionArgs('http://dvwa.test/?id=1','id','security=high'),{privateOutputDir:dir,timeout:1000});
  assert.equal(result.success,true);assert.equal(result.processStopped,true);assert.equal(result.processRef,current==='host'?31337:calls[0].args[calls[0].args.indexOf('--name')+1]);
  const command=calls[0];assert.equal(command.options.shell,false);
  if(current==='host')assert.ok(command.args.includes('--output-dir='+dir+'/output'));
  else {
   assert.ok(command.args.includes('--pull=never'));assert.ok(command.args.includes(dir+':/tmp/redteam-private'));
   assert.ok(!command.args.some(a=>a.includes('/tmp/redteam-output')));
   assert.equal(command.args.includes('--userns=keep-id'),current==='podman');
   assert.ok(command.args.includes('--output-dir=/tmp/redteam-private/output'));
  }
 }
});
test('cancelling real runner waits for container removal and reports aborted rather than positive',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'rt-runner-cancel-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 engine='docker';calls=[];mode='wait';const controller=new AbortController();
 const pending=runTool('sqlmap',sqlDetectionArgs('http://dvwa.test/?id=1','id',''),{privateOutputDir:dir,signal:controller.signal,timeout:1000});
 await new Promise(r=>setImmediate(r));controller.abort();const result=await pending;
 assert.equal(result.aborted,true);assert.equal(result.success,false);assert.equal(result.processStopped,true);
 assert.equal(calls.length,2);assert.deepEqual(calls[1].args.slice(0,2),['rm','-f']);
 assert.equal(calls[1].args[2],calls[0].args[calls[0].args.indexOf('--name')+1]);
});
