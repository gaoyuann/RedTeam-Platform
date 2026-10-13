import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import {readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {parseVariableContract} from '../src/services/executionVariables.js';

let replies=[], prompts=[], optionsSeen=[], onReply;
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async (messages,options)=>{
  prompts.push(structuredClone(messages));
  optionsSeen.push(options);
  onReply?.();
  const reply = replies.shift();
  return reply?.ok === false ? reply : {ok:true,content:typeof reply === 'string' ? reply : JSON.stringify(reply)};
}}});
const {generatePlaybook}=await import('../src/services/playbookGenerator.js');

async function fixture(t) {
  const db=getDb(':memory:');t.after(closeDb);
  const directory=fileURLToPath(new URL('../src/db/migrations/',import.meta.url));
  for (const name of (await readdir(directory)).sort()) {
    if (name.includes('import')) continue;
    const migration=await import(directory+name);(migration.default || migration.up)(db);
  }
  db.prepare("INSERT INTO users(username,password,role) VALUES ('alice','fixture','user')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by) VALUES ('s','http://example.test:8089/','web_scan','COMPLETED','alice')").run();
  prompts=[]; optionsSeen=[]; onReply=undefined;
  return db;
}
const plan=outputs=>({name:'Observed entry checks',description:'Fixture only',target_type:['web_url'],steps:[
  {name:'Probe entry',tool_id:'curl',args_template:['-I','<target>'],inputs:[],outputs},
  {name:'Probe headers',tool_id:'curl',args_template:['-I','<target>'],inputs:[],outputs:[]},
]});

test('unsupported tool report outputs are corrected once before a validated playbook is saved',async t=>{
  const db=await fixture(t);replies=[plan(['scan_results']),plan([])];
  const result=await generatePlaybook('s');
  assert.equal(result.ok,true);assert.equal(prompts.length,2);
  assert.match(prompts[0][1].content,/outputs MUST be \[\]/);
  assert.match(prompts[1].at(-1).content,/unsupported variable producer/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n,1);
  assert.deepEqual(db.prepare('SELECT output_variables FROM playbook_steps WHERE playbook_id=?').all(result.playbook_id).map(row=>JSON.parse(row.output_variables)),[[],[]]);
});

test('persistent unsupported dependencies are rejected without saving or executing a plan',async t=>{
  const db=await fixture(t);replies=[plan(['scan_results']),plan(['report'])];
  const result=await generatePlaybook('s');
  assert.equal(result.ok,false);assert.equal(prompts.length,2);
  assert.equal(result.code,'PLAYBOOK_VALIDATION_ERROR');
  assert.match(result.error,/unsupported variable producer/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n,0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM execution_runs').get().n,0);
});

test('plain and JSON fenced responses save valid steps without correction', async t => {
  const db = await fixture(t);
  for (const fence of ['```', '```json']) {
    replies = [`${fence}\n${JSON.stringify(plan([]))}\n\x60\x60\x60`];
    const result = await generatePlaybook('s');
    assert.equal(result.ok, true);
    assert.equal(result.steps_count, 2);
  }
  assert.equal(prompts.length, 2);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM execution_runs').get().n, 0);
});

test('malformed JSON is corrected once and has a distinct failure code', async t => {
  const db = await fixture(t);
  replies = ['not JSON', 'still not JSON'];
  const result = await generatePlaybook('s');
  assert.equal(result.code, 'PLAYBOOK_FORMAT_ERROR');
  assert.equal(prompts.length, 2);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n, 0);
});

test('provider failures are not retried and never expose provider bodies', async t => {
  const db = await fixture(t);
  for (const [error, code] of [
    ['LLM API 401: secret-fixture', 'LLM_AUTH_ERROR'],
    ['LLM API 429: secret-fixture', 'LLM_QUOTA_ERROR'],
    ['LLM request timed out', 'LLM_TIMEOUT'],
    ['No LLM API key configured.', 'LLM_NOT_CONFIGURED'],
    ['LLM request failed: secret-fixture', 'LLM_NETWORK_ERROR'],
  ]) {
    const before = prompts.length;
    replies = [{ok:false,error}];
    const result = await generatePlaybook('s');
    assert.equal(result.code, code);
    assert.doesNotMatch(JSON.stringify(result), /secret-fixture/);
    assert.equal(prompts.length, before + 1);
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n, 0);
});

test('correction shares the initial time budget and expired output is never saved', async t => {
  const db = await fixture(t);
  let now = 1000;
  t.mock.method(Date, 'now', () => now);
  onReply = () => { now += 70000; };
  replies = [plan(['report']), plan([])];
  const result = await generatePlaybook('s');
  assert.equal(result.code, 'LLM_TIMEOUT');
  assert.deepEqual(optionsSeen.map(options => options.timeoutMs), [120000, 50000]);
  assert.ok(optionsSeen.every(options => options.json === true));
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n, 0);
});

test('missing inputs and unknown tools stay invalid after correction', async t => {
  const db = await fixture(t);
  for (const change of [{inputs:['missing_value']}, {tool_id:'made_up_tool'}]) {
    const invalid = plan([]); Object.assign(invalid.steps[0], change);
    replies = [invalid, invalid];
    assert.equal((await generatePlaybook('s')).code, 'PLAYBOOK_VALIDATION_ERROR');
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n, 0);
});

test('verified DVWA login output can supply a later authenticated step', async t => {
  const db = await fixture(t);
  db.prepare("UPDATE scan_tasks SET completed_at=? WHERE scan_task_id='s'").run(new Date(Date.now() - 1000).toISOString());
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES ('s','http_probe',?,'httpx')")
    .run(JSON.stringify({url:'http://example.test:8089/',status_code:200,title:'DVWA',technologies:['DVWA']}));
  const dvwa = plan([]);
  dvwa.target_type = ['dvwa'];
  dvwa.steps = [
    {name:'Login',tool_id:'curl',args_template:['{{login_url}}','--data','username=fixture&password=fixture'],outputs:['dvwa_cookie','auth_cookie']},
    {name:'Authenticated headers',tool_id:'curl',args_template:['-I','{{sqli_url}}','-H','Cookie: {{auth_cookie}}'],inputs:['auth_cookie'],outputs:[]},
  ];
  replies = [dvwa, dvwa];
  const result = await generatePlaybook('s');
  assert.equal(result.ok, true, result.error);
  assert.equal(prompts.length, 1);
  assert.match(prompts[0][1].content, /Available target context variable names/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM execution_runs').get().n, 0);
});

test('DVWA sqlmap still requires a cookie producer even with empty inputs', async t => {
  const db = await fixture(t);
  db.prepare("UPDATE scan_tasks SET completed_at=? WHERE scan_task_id='s'").run(new Date(Date.now() - 1000).toISOString());
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool) VALUES ('s','http_probe',?,'httpx')")
    .run(JSON.stringify({url:'http://example.test:8089/',status_code:200,technologies:['DVWA']}));
  const invalid = plan([]);
  invalid.steps[1] = {name:'Requires session',tool_id:'sqlmap',args_template:['-u','{{sqli_url}}'],inputs:[],outputs:[]};
  replies = [invalid, invalid];
  const result = await generatePlaybook('s');
  assert.equal(result.code, 'PLAYBOOK_VALIDATION_ERROR');
  assert.match(result.error, /dvwa_cookie.*no value or preceding producer/);
  assert.match(prompts[1].at(-1).content, /implicitly needs dvwa_cookie/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n, 0);
});

test('cloud prompts advertise only variable names accepted by execution contracts', async t => {
  const db=await fixture(t);
  db.prepare("UPDATE scan_tasks SET target='fixture.amazonaws.com' WHERE scan_task_id='s'").run();
  replies=[plan([])];
  const result=await generatePlaybook('s');
  assert.equal(result.ok,true,result.error);
  const prompt=prompts[0][1].content;
  assert.match(prompt,/Target class: cloud/);
  const line=prompt.split('\n').find(line=>line.startsWith('Available target context variable names'));
  const names=line.split(': ')[1].split(', ');
  assert.ok(names.includes('aws_region'));
  assert.ok(!names.includes('s3_bucket'));
  assert.doesNotThrow(()=>parseVariableContract(names));
  // The fix must not relax the executor to admit unsupported names.
  assert.throws(()=>parseVariableContract(['s3_bucket']),/Variable contracts/);
});
