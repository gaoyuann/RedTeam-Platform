import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';

let model;
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:(...args)=>model(...args)}});
const {executeScan,requestScanAbort}=await import('../src/services/scanExecutor.js');
const {auditSources}=await import('../src/services/sourceAudit.js');

test('operator cancellation aborts report parsing immediately and prevents late model output from being imported',async t=>{
  const db=getDb(':memory:');t.after(closeDb);
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT OR IGNORE INTO users(username,password,role) VALUES ('alice','fixture','user')").run();
  const parameters={source_path:'/src/project'};
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,parameters,created_by) VALUES ('cancel-report','/src/project','source_scan','PARTIAL',?,'alice')")
    .run(JSON.stringify(parameters));
  const task=db.prepare("SELECT * FROM scan_tasks WHERE scan_task_id='cancel-report'").get();
  const markdown='src/input.c line 12: Unchecked copy';
  await auditSources(task,{db,parameters,nativeScan:async()=>({markdown,findings:[],parse_errors:['fixture failure'],flow_id:'91',finish_status:'acknowledged'})});
  let ready,release,modelSignal;
  const started=new Promise(resolve=>{ready=resolve;});
  model=async(_,options)=>{
    modelSignal=options.signal;ready();
    return new Promise(resolve=>{release=()=>resolve({ok:true,content:JSON.stringify({findings:[{
      file:'src/input.c',start_line:12,title:'Unchecked copy',reason:'Unchecked copy'}]})});});
  };
  const pending=executeScan(task.scan_task_id,{reportOnly:true});
  try {
    await started;
    requestScanAbort(task.scan_task_id);
    assert.equal(modelSignal.aborted,true,'abort must reach the parser before the 500ms polling interval');
  } finally {release();await pending;}
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='source_finding'").get().n,0);
  assert.equal(db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id=?').get(task.scan_task_id).status,'CANCELLED');
});
