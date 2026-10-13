import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import {readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';

let replies=[], prompts=[];
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async messages=>{
  prompts.push(structuredClone(messages));
  return {ok:true,content:JSON.stringify(replies.shift())};
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
  prompts=[];
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
  assert.match(result.error,/unsupported variable producer/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM playbooks WHERE generated_from='s'").get().n,0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM execution_runs').get().n,0);
});
