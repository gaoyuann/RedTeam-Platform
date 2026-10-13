import test from 'node:test';
import assert from 'node:assert/strict';
import {programExecutionTarget,programNetworkTarget} from '../src/services/programScan.js';
import {normalizeTopologyTarget} from '../src/services/nmapTopology.js';

test('separate application root and source directory survive legacy source input without treating files as runtime',()=>{
  const target='http://192.0.2.30:8089/';
  const resolve=(address,parameters)=>programExecutionTarget({target:address,parameters:JSON.stringify(parameters)});
  assert.equal(resolve(target,{input_kind:'source',source_url:target+'source/'}),target);
  assert.equal(programExecutionTarget({target,config:{input_kind:'source',source_url:target+'source/'}}),target);
  for(const [address,source_url] of [[target+'source/',target+'source/'],[target,undefined],
    [target,target],[target,'http://192.0.2.99:8089/source/'],[target,'https://192.0.2.30:8089/source/'],
    [target,'http://192.0.2.30:8090/source/'],[target+'?x=1',target+'source/'],[target+'/app/',target+'source/']])
    assert.equal(resolve(address,{input_kind:'source',source_url}),null);
  assert.equal(resolve(target+'source/',{input_kind:'source',runtime_target:'tcp://192.0.2.30:8091'}),'tcp://192.0.2.30:8091');
  assert.equal(resolve(target,{input_kind:'runtime'}),target);
});

test('network target preserves TCP port while task topology scopes to its host',()=>{
  assert.equal(programNetworkTarget('tcp://192.0.2.30:8091'),'192.0.2.30:8091');
  assert.equal(programNetworkTarget('tcp://[2001:db8::30]:8091'),'[2001:db8::30]:8091');
  assert.equal(normalizeTopologyTarget('tcp://192.0.2.30:8091'),'192.0.2.30');
  assert.equal(normalizeTopologyTarget('[2001:db8::30]:8091'),'2001:db8::30');
});
