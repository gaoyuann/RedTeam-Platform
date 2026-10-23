import test from 'node:test';import assert from 'node:assert/strict';
import {validatePostRequests,putPostRequests,getPostRequests,clearPostRequests} from '../src/services/scanPostRequests.js';
import {sqlDetectionArgs,sqlDetectionResult} from '../src/services/webSqlDetector.js';
import {createAnonymousWebSession} from '../src/services/anonymousWebSession.js';
const target='http://fixture.test/',template={url:target+'lookup',encoding:'json',fields:{id:'1'},parameters:['id'],read_only_confirmed:true};
test('explicit POST templates reject implicit authority, secrets and ambiguous data',()=>{
 for(const change of [{read_only_confirmed:false},{url:'http://other.test/'},{fields:{password:'secret'}},{fields:{id:{x:1}}},{parameters:['other']},{method:'DELETE'}])assert.throws(()=>validatePostRequests(target,[{...template,...change}],()=>true));
 putPostRequests('p','u',target,[template],()=>true);assert.equal(getPostRequests('p','other').length,0);assert.equal(getPostRequests('p','u')[0].body,'{"id":"1"}');clearPostRequests('p');assert.equal(getPostRequests('p','u').length,0);
});
test('form and JSON SQL requests preserve body method and report location',()=>{
 for(const encoding of ['form','json']){
  const e=validatePostRequests(target,[{...template,encoding}],()=>true)[0];const args=sqlDetectionArgs(e.url,'id','','Bearer fixture',e);assert.ok(args.includes('--method=POST'));assert.equal(args[args.indexOf('--data')+1],e.body);assert.ok(args[args.indexOf('--headers')+1].includes('Content-Type:'));
  const head=encoding==='json'?'JSON id ((custom) POST)':'id (POST)';
  const r={success:true,exitCode:0,processStopped:true,stdout:`Parameter: ${head}\n Type: boolean-based blind\n Title: fixture\n[*] ending @ 12:00`};
  assert.equal(sqlDetectionResult(r,'id',e).status,'tool_positive');assert.equal(sqlDetectionResult(r,'id').status,'inconclusive');
 }
});
test('POST page reads use same-scope authentication and never replay redirects',async()=>{
 let calls=0;const e=validatePostRequests(target,[template],()=>true)[0];
 const s=createAnonymousWebSession({target,allowUrl:()=>true,authentication:{type:'bearer',value:'private',origin:'http://fixture.test',path:'/'},request:async(u,o)=>{calls++;assert.equal(o.method,'POST');assert.equal(o.body,e.body);assert.equal(o.headers.Authorization,'Bearer private');return new Response('',{status:302,headers:{location:'/next'}});}});
 await assert.rejects(s.readEntry(e),/POST 跳转被拒绝/);assert.equal(calls,1);s.close();
});

test('POST URL must be explicitly specified without normalization of query or fragments',()=>{
 for(const url of [undefined,null,3,'','  ','/lookup','http://fixture.test/lookup#x','http://fixture.test/lookup#','http://fixture.test/lookup?','http://u:p@fixture.test/lookup',' http://fixture.test/lookup']){
  assert.throws(()=>validatePostRequests(target,[{...template,url}],()=>true));
 }
 assert.equal(validatePostRequests(target,[template],()=>true)[0].url,template.url);
});
test('template values redact reflections while preserving generated references and operational enums',async()=>{
 const {createPostRedactor}=await import('../src/services/scanPostRequests.js');
 const entries=validatePostRequests(target,[{...template,fields:{id:'1',search:'private value/路径',case:'positive'}}],()=>true);
 const redactor=createPostRedactor(entries);
 for(const reflection of ['private value/路径',encodeURIComponent('private value/路径'),encodeURIComponent(encodeURIComponent('private value/路径'))]){
  assert.equal(redactor.identitySafe(target+'echo/'+reflection),false);
  assert.doesNotMatch(JSON.stringify(redactor.scrub({url:target+'echo/'+reflection,reason:reflection})),/private/);
 }
 const id='21111111-1111-1111-1111-111111111111';
 assert.equal(redactor.scrub({tool_run_id:id}).tool_run_id,id);
 assert.equal(redactor.scrub({status:'tool_positive'}).status,'tool_positive');
 assert.equal(redactor.identitySafe('http://127.0.0.1:18081/lookup'),true);
 redactor.close();
});
