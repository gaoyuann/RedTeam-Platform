import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import express from 'express';
import {fileURLToPath} from 'node:url';
import {runMigrations} from '../src/db/migrate.js';
import scanRoutes from '../src/routes/scans.js';
import {scanPage} from '../src/services/scanResultQuery.js';

test('source detail and task collection publish findings only after scan and report processing end',async t=>{
  const db=new Database(':memory:');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role) VALUES ('source-reader','fixture','user')").run();
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES ('source-pipe','http://example.test/source/','running','source-reader','source-final','{}')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES ('source-final','http://example.test/source/','source_scan','RUNNING','source-reader','source-pipe')").run();
  const insert=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES (?,?,?,?,?)');
  const coverageId=insert.run('source-final','source_coverage',JSON.stringify({cscan:{state:'parsing',scan_complete:true}}),'info','cscan').lastInsertRowid;
  const findingId=insert.run('source-final','source_finding',JSON.stringify({file:'src/input.c',start_line:12,title:'Unchecked copy',reason:'No bound check',severity:'high'}),'high','cscan').lastInsertRowid;
  insert.run('source-final','raw_output',JSON.stringify({report:'retained report',complete:true}),'info','cscan');
  const app=express();app.use((req,res,next)=>{req.user={sub:'source-reader',role:'user'};next();});app.use('/scans',scanRoutes(db));
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));db.close();});
  const detail=async()=>{
    const response=await fetch('http://127.0.0.1:'+server.address().port+'/scans/source-final');
    assert.equal(response.status,200);return (await response.json()).data;
  };
  const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='source-pipe'").get();
  for(const phase of ['running','parsing','importing']) {
    db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({cscan:{state:phase,scan_complete:phase!=='running'}}),coverageId);
    const row=await detail();assert.equal(row.source_scan.pending,true);assert.equal(row.source_scan.phase,phase);
    assert.equal(row.results.some(r=>r.result_type==='source_finding'),false);
    assert.ok(row.results.some(r=>r.result_type==='raw_output'),'raw evidence remains available');
    const page=scanPage(db,pipeline,{category:'vulnerability'});
    assert.equal(page.page.total,0);assert.equal(page.scan_records.length,0);
    assert.equal(page.scan_sources[0].source_scan.pending,true);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM scan_results WHERE id=?').get(findingId).n,1,'publication never deletes retained findings');
  }
  db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id='source-final'").run();
  db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({cscan:{state:'finished',scan_complete:true},cscan_complete:true}),coverageId);
  const done=await detail();assert.equal(done.source_scan.findings_ready,true);assert.equal(done.source_scan.findings_count,1);
  assert.equal(done.results.filter(r=>r.result_type==='source_finding').length,1);
  const published=scanPage(db,pipeline,{category:'vulnerability'});
  assert.equal(published.page.total,1);assert.equal(published.scan_records[0].id,Number(findingId));
  // Reparse reuses the same rows but cannot expose intermediate results.
  db.prepare("UPDATE scan_tasks SET status='RUNNING' WHERE scan_task_id='source-final'").run();
  assert.equal((await detail()).results.some(r=>r.result_type==='source_finding'),false);
  db.prepare("UPDATE scan_tasks SET status='PARTIAL' WHERE scan_task_id='source-final'").run();
  assert.equal((await detail()).results.find(r=>r.result_type==='source_finding').id,Number(findingId));
});
