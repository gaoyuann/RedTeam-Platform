import test from 'node:test';
import assert from 'node:assert/strict';
import {putScanSessionAuth,scanSessionAuth,clearScanSessionAuth,scrubSession,sessionAllows} from '../src/services/scanSessionAuth.js';
import {createAnonymousWebSession} from '../src/services/anonymousWebSession.js';
import {sqlDetectionArgs} from '../src/services/webSqlDetector.js';
test('temporary sessions are owner-bound, validated, scoped and cleared',()=>{
 const target='https://fixture.test/app/';
 for(const value of [{type:'cookie',value:'SID=secret\r\nInjected: value'},{type:'bearer',value:'two words'},{type:'cookie',value:'invalid'},{type:'cookie',value:'a=b',url:'https://foreign/'}])assert.throws(()=>putScanSessionAuth('p','u',target,value));
 putScanSessionAuth('p','u',target,{type:'cookie',value:'SID=opaque-secret; role=teaching'});
 try {
  assert.equal(scanSessionAuth('p','other'),null);assert.throws(()=>putScanSessionAuth('p','u',target,{type:'bearer',value:'another'}));
  const auth=scanSessionAuth('p','u');assert.equal(sessionAllows(auth,target+'entry'),true);
  for(const url of ['https://fixture.test/application/','http://fixture.test/app/','https://fixture.test:444/app/','https://other.test/app/'])assert.equal(sessionAllows(auth,url),false);
  assert.doesNotMatch(JSON.stringify(scrubSession(auth,{text:'opaque-secret SID=opaque-secret; role=teaching'})),/opaque-secret|teaching/);
 }finally{clearScanSessionAuth('p');}assert.equal(scanSessionAuth('p','u'),null);
});
test('cookie and bearer reach only same-scope requests, never off-scope redirect',async()=>{
 for(const type of ['cookie','bearer']){
  const auth={type,value:type==='cookie'?'SID=private':'private',origin:'https://fixture.test',path:'/app/'};let calls=0;
  const s=createAnonymousWebSession({target:'https://fixture.test/app/',allowUrl:()=>true,authentication:auth,request:async(url,opts)=>{
   calls++;assert.deepEqual(opts.headers,type==='cookie'?{Cookie:auth.value}:{Authorization:'Bearer private'});
   return calls===1?new Response('<h1>Ordinary protected app</h1>'):new Response('',{status:302,headers:{location:'https://foreign.test/'}});
  }});
  await s.login();await assert.rejects(s.read('https://fixture.test/app/page'),/超出允许范围/);assert.equal(calls,2);s.close();
 }
});
test('expired session fails before SQL dispatch instead of presenting login as authenticated success',async()=>{
 for(const response of [()=>new Response('',{status:401}),()=>new Response('<form><input type="password"></form>')]){
  const s=createAnonymousWebSession({target:'https://fixture.test/',allowUrl:()=>true,authentication:{type:'bearer',value:'private',origin:'https://fixture.test',path:'/'},request:async()=>response()});
  await assert.rejects(s.login(),/临时会话/);s.close();
 }
});
test('controlled SQL policy forwards authorization without changing detection scope',()=>{
 const args=sqlDetectionArgs('https://fixture.test/app/?id=1','id','','Bearer private');
 assert.equal(args[args.indexOf('--headers')+1],'Authorization: Bearer private');assert.ok(args.includes('--ignore-redirects'));assert.ok(args.includes('--technique=BEU'));
});

test('tool command diagnostics redact complete header arguments',async()=>{
 const {redactToolArgs}=await import('../src/tools/toolContracts.js');
 assert.doesNotMatch(JSON.stringify(redactToolArgs(['--headers','Authorization: Bearer secret-session','--headers=Cookie: arbitrary=private-value'],'sqlmap')),/secret-session|private-value/);
});
