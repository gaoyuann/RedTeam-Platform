import test from 'node:test';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';import {runMigrations} from '../src/db/migrate.js';
import {executeScan} from '../src/services/scanExecutor.js';import {createScanBudget} from '../src/services/scanBudget.js';
test('HTTP deadline and external zero budget never leave running or stop-unknown records',async t=>{
 const db=getDb(':memory:');t.after(closeDb);await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','fixture','user')").run();
 for(const [type,target,budget] of [['app_discovery','http://fixture.test/',createScanBudget({duration_ms:0})],['port_scan','192.0.2.1',createScanBudget({tools:0})]]){
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,created_by) VALUES (?,?,?,'owner')").run(type,target,type);
  const result=await executeScan(type,{budget});assert.equal(result.ok,false);
  const runs=db.prepare('SELECT state,outcome FROM scan_tool_runs WHERE scan_task_id=?').all(type);
  assert.equal(runs.some(r=>r.state==='running'||JSON.parse(r.outcome||'{}').stopped===false),false);
  if(type==='app_discovery')assert.equal(runs.length,0);
  else {assert.equal(runs.length,1);assert.equal(JSON.parse(runs[0].outcome).tool_started,false);assert.equal(JSON.parse(runs[0].outcome).stopped,true);}
 }
});
