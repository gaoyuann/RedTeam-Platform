import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTaskScope, isTargetInScope, scopeBlockReason, scopeConditions } from '../src/services/taskScope.js';
import { validateExecutionScope } from '../src/services/executionScope.js';
import { probeTarget } from '../src/services/targetDiscovery.js';

test('structured scope bounds hosts, URLs, CIDRs and exclusions', () => {
  const scope=normalizeTaskScope({task_scope:{
    includes:['192.0.2.0/28','https://example.invalid/app/'],
    excludes:['192.0.2.3','https://example.invalid/app/admin/'],
    execution_location:'scanner',discovery_budget:3,
  }},'https://example.invalid/app/');
  assert.equal(isTargetInScope(scope,'192.0.2.2'),true);
  assert.equal(isTargetInScope(scope,'192.0.2.3'),false);
  assert.equal(isTargetInScope(scope,'192.0.2.17'),false);
  assert.equal(isTargetInScope(scope,'https://example.invalid/app/check'),true);
  assert.equal(isTargetInScope(scope,'https://example.invalid/app/admin/'),false);
  assert.equal(isTargetInScope(scope,'https://example.invalid/other'),false);
  assert.equal(isTargetInScope(scope,'http://example.invalid/app/'),false);
  assert.equal(isTargetInScope(scope,'https://example.invalid/app/%2fadmin'),false);
  assert.match(scopeBlockReason(scope,'https://example.invalid/app/','web_scan'),/授权 URL 路径|排除/);
  assert.equal(scopeBlockReason(scope,'https://example.invalid/app/check','target-request'),null);
  assert.throws(()=>normalizeTaskScope({task_scope:{includes:['192.0.2.0/28'],excludes:['192.0.2.1']}},'192.0.2.1'),/排除/);
  assert.throws(()=>normalizeTaskScope({task_scope:{includes:['https://example.invalid/app/']}},'https://other.invalid/'),/包含/);
});

test('remote prerequisite and execution requests are checked against task scope', () => {
  const scope=normalizeTaskScope({task_scope:{includes:['https://example.invalid/app/'],excludes:['https://example.invalid/app/admin/'],execution_location:'remote'}},'https://example.invalid/app/');
  assert.deepEqual(scopeConditions(scope),['远端扫描位置尚未配置和联调']);
  const request=url=>validateExecutionScope({target:'https://example.invalid/app/',toolId:'target-request',args:[JSON.stringify({url})],scope});
  assert.equal(request('https://example.invalid/app/check').allowed,true);
  assert.equal(request('https://example.invalid/app/admin/').allowed,false);
  assert.equal(request('https://other.invalid/app/').allowed,false);
  assert.equal(validateExecutionScope({target:'https://example.invalid/app/',toolId:'nikto',args:['-h','https://example.invalid/app/'],scope}).allowed,false);
  const cidr=normalizeTaskScope({task_scope:{includes:['192.0.2.0/28'],excludes:['192.0.2.3']}},'192.0.2.0/28');
  assert.equal(validateExecutionScope({target:'192.0.2.0/28',toolId:'nmap',args:['-sV','192.0.2.0/28'],scope:cidr}).allowed,false);
  const path=normalizeTaskScope({task_scope:{includes:['http://fixture.invalid/app/']}},'http://fixture.invalid/app/');
  assert.match(scopeBlockReason(path,'http://fixture.invalid/app/','web_scan'),/授权 URL 路径/);
  assert.equal(scopeBlockReason(path,'http://fixture.invalid/app/','app_discovery'),null);
});

test('controlled HTTP probe never follows a redirect outside the structured path',async()=>{
  const scope=normalizeTaskScope({task_scope:{includes:['http://fixture.invalid/app/']}},'http://fixture.invalid/app/');
  let requests=0;
  await assert.rejects(probeTarget('http://fixture.invalid/app/',{
    allowUrl:url=>isTargetInScope(scope,url),
    request:async()=>{requests++;return new Response('redirect',{status:302,headers:{location:'/outside'}});},
  }),error=>error.partialResults.length===1 && /scope/.test(error.message));
  assert.equal(requests,1);
});

test('IP task validation rejects explicit tool destinations outside its scope',()=>{
  const scope=normalizeTaskScope({task_scope:{includes:['192.0.2.2']}},'192.0.2.2');
  assert.equal(validateExecutionScope({target:'192.0.2.2',toolId:'nikto',args:['-h','http://198.51.100.5/'],scope}).allowed,false);
  assert.equal(validateExecutionScope({target:'192.0.2.2',toolId:'nmap',args:['-sV','192.0.2.2','198.51.100.5'],scope}).allowed,false);
  assert.equal(validateExecutionScope({target:'192.0.2.2',toolId:'nmap',args:['-sV','192.0.2.2'],scope}).allowed,true);
});
