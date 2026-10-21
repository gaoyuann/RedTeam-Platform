import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { checkWebDirectory } from '../src/services/webDirectoryProbe.js';
import { runTargetRequest } from '../src/tools/targetRequest.js';

const response=(status,body='page',headers={})=>({success:true,stdout:JSON.stringify({complete:true,truncated:false,
  status_code:status,response:body,response_headers:headers})});

test('normal directory uses three bounded GETs and stores fingerprints, never bodies or cookies',async()=>{
  const calls=[];
  const result=await checkWebDirectory('http://fixture.invalid/app/',{cookie:'session=fixture-secret',request:async spec=>{
    calls.push(spec);assert.equal(spec.method,'GET');assert.equal(spec.timeout_ms,5000);
    assert.equal(spec.headers.cookie,'session=fixture-secret');
    return response(calls.length===1?200:404,calls.length===1?'private page fixture-secret':'not found');
  }});
  assert.equal(result.allowed,true);assert.equal(calls.length,3);
  assert.ok(calls.every(spec=>new URL(spec.url).pathname.startsWith('/app/')));
  assert.notEqual(calls[1].url,calls[2].url);
  assert.doesNotMatch(JSON.stringify(result),/fixture-secret|private page/);
});

test('wildcards, login redirects, dynamic soft errors and protected missing paths stop dictionary scans',async()=>{
  for(const [status,body] of [[200,'login'],[302,''],[403,'forbidden'],[500,'error']]) {
    let n=0;
    const result=await checkWebDirectory('http://fixture.invalid/',{request:async()=>response(++n===1?200:status,body+n,{location:'/login.php'})});
    assert.equal(result.allowed,false,String(status));assert.equal(n,3);
  }
  const result=await checkWebDirectory('http://fixture.invalid/',{request:async()=>response(200,'same page')});
  assert.equal(new Set(result.evidence.map(x=>x.sha256)).size,1);
  assert.equal(result.allowed,false);
});

test('login forms and JSON endpoints are rejected even with directory-shaped URLs',async()=>{
  for(const [body,headers] of [
    ['<form action=""><input type=password></form>',{}],
    ['<form method=post></form>',{}],['{}',{'content-type':'application/json'}],
  ]) {
    let calls=0;
    const result=await checkWebDirectory('http://fixture.invalid/login/',{request:async()=>{calls++;return response(200,body,headers);}});
    assert.equal(result.allowed,false);assert.equal(calls,1);
  }
});

test('scope, failure, truncation and cancellation never fall through to scanning',async()=>{
  let calls=0;
  const scoped=await checkWebDirectory('http://fixture.invalid/app/',{
    allowUrl:url=>!url.includes('__rt_missing_'),request:async()=>{calls++;return response(200);}});
  assert.equal(scoped.allowed,false);assert.equal(calls,1);
  for(const value of [{success:false,timedOut:true},{success:false,aborted:true},
    {success:true,stdout:'invalid'}, {success:true,stdout:JSON.stringify({complete:true,truncated:true,status_code:200,response:'partial'})}]) {
    calls=0;
    const result=await checkWebDirectory('http://fixture.invalid/',{request:async()=>{calls++;return value;}});
    assert.equal(result.allowed,false);assert.equal(calls,1);
  }
  assert.equal((await checkWebDirectory('http://fixture.invalid/',{request:async()=>{throw new Error('connection refused');}})).allowed,false);
});

test('API prefix without index can be checked without treating the base 404 as unavailable',async()=>{
  const options={request:async()=>response(404,'not found')};
  assert.equal((await checkWebDirectory('http://fixture.invalid/api/',options)).allowed,false);
  assert.equal((await checkWebDirectory('http://fixture.invalid/api/',{...options,allowMissingBase:true})).allowed,true);
});

test('real bounded HTTP adapter does not follow redirects and detects identical missing-page responses',async()=>{
  const visited=[];
  const server=http.createServer((req,res)=>{
    visited.push(req.url);
    if(req.url==='/') {res.writeHead(302,{location:'/outside-login'});res.end();}
    else {res.writeHead(200,{'content-type':'text/html'});res.end('same login page');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const target=`http://127.0.0.1:${server.address().port}/`;
    const result=await checkWebDirectory(target,{request:spec=>runTargetRequest([JSON.stringify(spec)],{target})});
    assert.equal(result.allowed,false);assert.equal(visited.length,3);
    assert.equal(visited.includes('/outside-login'),false);
  } finally {await new Promise(resolve=>server.close(resolve));}
});
