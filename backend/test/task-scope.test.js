import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTaskScope, isTargetInScope, scopeBlockReason, scopeConditions, topologyDiscoveryScope } from '../src/services/taskScope.js';

test('TCP runtime scopes accept both URL forms when moving tasks between environments', () => {
  for (const target of ['tcp://192.0.2.30:8091', 'tcp://192.0.2.30:8091/']) {
    const scope = normalizeTaskScope({}, target);
    assert.equal(isTargetInScope(scope, 'tcp://192.0.2.30:8091'), true);
    assert.equal(isTargetInScope(scope, 'tcp://192.0.2.30:8092'), false);
  }
});
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

test('single IPv4 topology discovery has a separate scope and preserves host exclusions', () => {
  for (const target of ['192.0.2.2', 'http://192.0.2.2:8080/app/', 'tcp://192.0.2.2:8091']) {
    const scope = normalizeTaskScope({task_scope:{excludes:[
      '192.0.2.3', '192.0.2.16/28', 'http://192.0.2.4:8080/private/', 'tcp://192.0.2.3:22', '/src/fixture/private',
    ]}}, target);
    const before = JSON.stringify(scope);
    const discovery = topologyDiscoveryScope(scope, target, '192.0.2.0/26');
    assert.deepEqual(discovery, {includes:['192.0.2.0/26'], excludes:['192.0.2.3','192.0.2.16/28','192.0.2.4']});
    assert.equal(isTargetInScope(discovery, '192.0.2.5'), true);
    for (const host of ['192.0.2.3','192.0.2.4','192.0.2.20','192.0.2.65'])
      assert.equal(isTargetInScope(discovery, host), false);
    assert.equal(isTargetInScope(scope, '192.0.2.5'), false);
    assert.match(scopeBlockReason(scope, '192.0.2.5', 'port_scan'), /超出任务范围/);
    assert.equal(JSON.stringify(scope), before, 'the execution scope is never expanded');
    assert.equal(topologyDiscoveryScope(scope, target, '198.51.100.0/24'), null);
  }
});

test('topology discovery keeps legacy and explicit CIDR scopes without expanding other targets', () => {
  for (const target of ['example.invalid', 'https://example.invalid/', '2001:db8::2', '192.0.2.0/28', '/src/fixture']) {
    const scope = normalizeTaskScope({}, target);
    assert.equal(topologyDiscoveryScope(scope, target, '192.0.2.0/24'), null);
  }
  const explicit = normalizeTaskScope({task_scope:{includes:['192.0.2.0/24'],excludes:['192.0.2.3']}}, '192.0.2.2');
  assert.deepEqual(topologyDiscoveryScope(explicit, '192.0.2.2', '192.0.2.0/24'),
    {includes:['192.0.2.0/24'],excludes:['192.0.2.3']});
  assert.deepEqual(topologyDiscoveryScope(null, 'example.invalid', '192.0.2.0/24'),
    {includes:['192.0.2.0/24'],excludes:[]});
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

test('host task validation binds non-Web network tools to an allowed host',()=>{
  const scope=normalizeTaskScope({task_scope:{includes:['fixture.invalid']}},'fixture.invalid');
  const check=(toolId,args)=>validateExecutionScope({target:'fixture.invalid',toolId,args,scope}).allowed;
  assert.equal(check('hydra',['-L','users.txt','-P','passwords.txt','outside.invalid','ssh']),false);
  assert.equal(check('hydra',['-L','users.txt','-P','passwords.txt','smb://outside.invalid','smb']),false);
  assert.equal(check('netexec',['smb','outside.invalid','--shares']),false);
  assert.equal(check('evil-winrm',['-i','outside.invalid','-u','user']),false);
  assert.equal(check('ssh-exec',['-i','outside.invalid','-u','user']),false);
  assert.equal(check('rpcclient',['-N','-U','','outside.invalid']),false);
  assert.equal(check('netexec',['smb','fixture.invalid','--shares']),true);
  assert.equal(check('hydra',['-L','users.txt','-P','passwords.txt','smb://fixture.invalid']),true,
    'service URI syntax remains usable for the allowed host');
});
