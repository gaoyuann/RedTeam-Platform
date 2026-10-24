import test,{mock} from 'node:test';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';import {runMigrations} from '../src/db/migrate.js';import {putScanSessionAuth} from '../src/services/scanSessionAuth.js';
let analysis=0;
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async messages=>{
 const c=JSON.parse(messages[1].content).candidates[0];return {ok:true,content:JSON.stringify({action:'execute_check',check_id:c.check_id,evidence_id:c.source_record_id,reason:'fixture'})};
},callLlmReact:async()=>''}});
await mock.module('../src/services/scanExecutor.js',{namedExports:{requestScanAbort:()=>{},executeScan:async id=>{
 const db=getDb();db.prepare("UPDATE scan_tasks SET status='PARTIAL' WHERE scan_task_id=?").run(id);
 db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'web_scan_summary','{\"checks_started\":0}')").run(id);
 return {ok:true,status:'PARTIAL'};
}}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async()=>{analysis++;throw Error('must not run');}}});
const {runPipeline}=await import('../src/services/pipelineEngine.js');
test('parent does not enter analysis or generate after parameter tool never started',async t=>{
 const db=getDb(':memory:');t.after(closeDb);await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','fixture','user')").run();
 const config={scan_orchestrator:{version:1,mode:'react'},task_scope:{includes:['http://fixture.test/'],excludes:[]}};
 db.prepare("INSERT INTO pipelines(pipeline_id,target,status,config,created_by) VALUES ('gate','http://fixture.test/','created',?,'owner')").run(JSON.stringify(config));
 putScanSessionAuth('gate','owner','http://fixture.test/',{type:'bearer',value:'fixture'});
 await runPipeline('gate');assert.equal(analysis,0);
 assert.equal(db.prepare("SELECT status FROM pipelines WHERE pipeline_id='gate'").get().status,'failed');
 assert.equal(db.prepare("SELECT count(*) n FROM pipeline_steps WHERE pipeline_id='gate' AND step_type IN ('analyze','generate')").get().n,0);
});
