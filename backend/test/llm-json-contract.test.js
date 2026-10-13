import test from 'node:test';
import assert from 'node:assert/strict';
import {getDb,closeDb} from '../src/db/connection.js';
import {callLlm} from '../src/services/llmClient.js';

test('source JSON requests use DeepSeek JSON mode, preserve other gateway contracts and reject empty replies',async t=>{
  const db=getDb(':memory:');t.after(closeDb);
  db.exec('CREATE TABLE system_config(config_key TEXT PRIMARY KEY,config_value TEXT,category TEXT)');
  const keys=['LLM_API_KEY','LLM_BASE_URL','LLM_MODEL'];
  const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  t.after(()=>{for(const key of keys) {if(previous[key]===undefined) delete process.env[key];else process.env[key]=previous[key];}});
  process.env.LLM_API_KEY='fixture-only';process.env.LLM_MODEL='fixture';
  const messages=[{role:'user',content:'Return JSON: {"findings":[]}'}],requests=[];
  let content='{"findings":[]}';
  t.mock.method(globalThis,'fetch',async(url,options)=>{
    requests.push({url,body:JSON.parse(options.body)});
    return {ok:true,json:async()=>({choices:[{message:{content}}]})};
  });
  process.env.LLM_BASE_URL='https://api.deepseek.com/v1';
  assert.equal((await callLlm(messages,{json:true})).ok,true);
  assert.deepEqual(requests.at(-1).body.response_format,{type:'json_object'});
  await callLlm(messages);assert.equal(requests.at(-1).body.response_format,undefined);
  process.env.LLM_BASE_URL='https://gateway.fixture.invalid/v1';
  await callLlm(messages,{json:true});assert.equal(requests.at(-1).body.response_format,undefined);
  content='   ';assert.deepEqual(await callLlm(messages,{json:true}),{ok:false,error:'LLM returned empty JSON content'});
});

test('reasoning-only and truncated replies expose safe metadata without replacing final content', async t => {
  const db=getDb(':memory:');t.after(closeDb);
  db.exec('CREATE TABLE system_config(config_key TEXT PRIMARY KEY,config_value TEXT,category TEXT)');
  const keys=['LLM_API_KEY','LLM_BASE_URL','LLM_MODEL'];
  const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  t.after(()=>{for(const key of keys) {if(previous[key]===undefined) delete process.env[key];else process.env[key]=previous[key];}});
  process.env.LLM_API_KEY='fixture-only';process.env.LLM_BASE_URL='https://fixture.invalid/v1';process.env.LLM_MODEL='fixture';
  let response={choices:[{finish_reason:'length',message:{content:null,reasoning_content:'private-reasoning-fixture'}}]};
  t.mock.method(globalThis,'fetch',async()=>({ok:true,json:async()=>response}));
  const result=await callLlm([{role:'user',content:'Reply OK'}]);
  assert.equal(result.ok,true);
  assert.equal(result.content,'');
  assert.equal(result.hasReasoning,true);
  assert.equal(result.finishReason,'length');
  assert.doesNotMatch(JSON.stringify(result),/private-reasoning-fixture/);
  // A connection response is not a usable JSON playbook.
  assert.deepEqual(await callLlm([],{json:true}),{ok:false,error:'LLM returned empty JSON content'});
  for (const data of [{}, {choices:[]}, {choices:[{message:{content:{unexpected:true},reasoning_content:' '}}]}]) {
    response=data;
    const malformed=await callLlm([]);
    assert.equal(malformed.content,'');
    assert.equal(malformed.hasReasoning,false);
  }
});
