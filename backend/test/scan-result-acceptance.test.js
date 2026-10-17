import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {parseScanOutput,createScanOutputCollector} from '../src/services/scanResultParsers.js';
import {finishToolRun,beginToolRun} from '../src/services/scanResultStore.js';
import {scanPage} from '../src/services/scanResultQuery.js';
import {resultCategory} from '../src/services/scanResultCatalog.js';
import migrate from '../src/db/migrations/029_scan_result_integrity.js';

function fixture() {
 const db=new Database(':memory:');db.pragma('foreign_keys=ON');
 db.exec(`CREATE TABLE pipelines(pipeline_id TEXT PRIMARY KEY,target TEXT,created_by TEXT,scan_task_id TEXT,config TEXT);
 CREATE TABLE pipeline_steps(id INTEGER PRIMARY KEY,pipeline_id TEXT,step_order INTEGER,step_type TEXT,input_data TEXT,output_data TEXT);
 CREATE TABLE scan_tasks(id INTEGER PRIMARY KEY,scan_task_id TEXT UNIQUE,target TEXT,created_by TEXT,scan_type TEXT,status TEXT);
 CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT REFERENCES scan_tasks(scan_task_id) ON DELETE CASCADE,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT);`);
 migrate(db);
 db.exec("INSERT INTO pipelines VALUES ('p','http://fixture.invalid','alice','ports,web','{}'); INSERT INTO pipeline_steps(pipeline_id,step_order,step_type,input_data) VALUES ('p',0,'scan','{\"scan_types\":[\"port_scan\",\"web_scan\"]}');");
 for(const [id,type,status] of [['ports','port_scan','COMPLETED'],['web','web_scan','PARTIAL']])
  db.prepare('INSERT INTO scan_tasks(scan_task_id,target,created_by,scan_type,status,pipeline_id) VALUES (?,?,?,?,?,?)').run(id,'http://fixture.invalid','alice',type,status,'p');
 return db;
}

test('acceptance: mixed subscans reconcile parser, storage and every API page',()=>{
 const db=fixture();
 try {
  const nmap=parseScanOutput('port_scan','Nmap scan report for fixture.invalid\nHost is up.\n80/tcp open http\n');
  const lines=Array.from({length:240},(_,i)=>`[template-${i}] [http] [${i%6===0?'info':'high'}] http://fixture.invalid/${i}`).join('\n');
  const collector=createScanOutputCollector('vuln_scan');
  const bytes=Buffer.from(lines+'\nfixture unrecognized line\n');
  for(let i=0;i<bytes.length;i+=113) collector.push(bytes.subarray(i,i+113),'stdout');
  const parsed=collector.finish({});
  parsed.records.push({result_type:'scan_error',result_data:{error:'fixture timeout'},severity:'info',source_tool:'nuclei'});
  for(const [id,tool,type,result,output] of [
   ['ports','nmap','port_scan',{success:true,exitCode:0},nmap],
   ['web','nuclei','vuln_scan',{success:false,exitCode:-1,timedOut:true},parsed]
  ]) finishToolRun(db,beginToolRun(db,id,tool,type),id,tool,result,output);
  const pipeline=db.prepare('SELECT * FROM pipelines').get();let after=0,through;const ids=[];
  do {
   const page=scanPage(db,pipeline,{after,limit:37,...(through===undefined?{}:{through})});
   through=page.page.through;after=page.page.next_after;ids.push(...page.scan_records.map(r=>r.id));
   assert.equal(page.scan_summary.completeness,'incomplete');
   assert.equal(Object.values(page.scan_summary.categories).reduce((a,b)=>a+b,0),page.page.total);
   if(!page.page.has_more)break;
  }while(true);
  const stored=db.prepare('SELECT * FROM scan_results ORDER BY id').all();
  assert.deepEqual(ids,stored.map(r=>r.id));
  assert.equal(stored.filter(r=>resultCategory(r)==='vulnerability').length,200);
  assert.equal(stored.filter(r=>resultCategory(r)==='information').length,40);
  for(const run of db.prepare('SELECT * FROM scan_tool_runs').all()) assert.equal(JSON.parse(run.diagnostics).persisted_records,stored.filter(r=>r.tool_run_id===run.tool_run_id).length);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 } finally {db.close();}
});

test('acceptance: streaming and buffered parsing have the same classification and reconciliation',()=>{
 const text='[INF] fixture progress\n[one] [http] [info] http://fixture.invalid/中文\n[two] [http] [high] http://fixture.invalid/\nunknown fixture line\n';
 const buffered=parseScanOutput('vuln_scan',text);
 const stream=createScanOutputCollector('vuln_scan');
 const bytes=Buffer.from(text);for(let i=0;i<bytes.length;i++)stream.push(bytes.subarray(i,i+1));
 const observed=stream.finish({});
 assert.deepEqual(observed.records,buffered.records);
 assert.equal(observed.diagnostics.unparsed_lines,buffered.diagnostics.unparsed_lines);
 assert.equal(observed.diagnostics.ignored_lines,buffered.diagnostics.ignored_lines);
});

test('acceptance: completed task cannot claim completeness while a tool is still running',()=>{
 const db=fixture();
 try {
  db.exec("UPDATE scan_tasks SET status='COMPLETED';");
  for(const id of ['ports','web']) {
   const run=beginToolRun(db,id,'fixture','vuln_scan');
   finishToolRun(db,run,id,'fixture',{success:true,exitCode:0},{records:[],diagnostics:{unparsed_lines:0}});
  }
  beginToolRun(db,'web','fixture','vuln_scan');
  const summary=scanPage(db,db.prepare('SELECT * FROM pipelines').get()).scan_summary;
  assert.equal(summary.active_calls.length,1);
  assert.notEqual(summary.completeness,'complete');
 } finally {db.close();}
});

test('acceptance: information severity is case insensitive in old JSON results',()=>{
 assert.equal(resultCategory({result_type:'auth_finding',severity:'INFO'}),'information');
});

test('acceptance: migration retains pre-existing finding, run, report and source verification references',async()=>{
 const db=new Database(':memory:');db.pragma('foreign_keys=ON');
 try {
  for(const name of ['001_create_tables','005_add_scan_ref','013_add_pipeline_tables','025_source_audits']) {
   const migration=await import('../src/db/migrations/'+name+'.js');(migration.default || migration.up)(db);
  }
  db.exec(`INSERT INTO users(username,password,role) VALUES ('alice','fixture','user');
   INSERT INTO pipelines(pipeline_id,target,created_by,scan_task_id) VALUES ('old-p','fixture.invalid','alice','old-s');
   INSERT INTO scan_tasks(scan_task_id,target,scan_type,created_by,status) VALUES ('old-s','fixture.invalid','source_scan','alice','COMPLETED');
   INSERT INTO scan_results(id,scan_task_id,result_type,result_data,severity) VALUES (41,'old-s','source_finding','{"title":"legacy fixture"}','medium');
   INSERT INTO execution_runs(run_id,scan_task_id,user_sub) VALUES ('old-run','old-s','alice');
   INSERT INTO test_reports(report_id,title,run_id,scan_task_id,content) VALUES ('old-report','legacy','old-run','old-s','{"legacy":true}');
   INSERT INTO source_verifications(finding_id,run_id,status,evidence_ids,note,reviewed_by,created_at) VALUES (41,'old-run','inconclusive','[]','fixture','alice','2026-10-17');`);
  const tables=['scan_results','execution_runs','test_reports','source_verifications'];
  const previous=Object.fromEntries(tables.map(table=>[table,db.prepare(`SELECT * FROM ${table}`).all()]));
  migrate(db);migrate(db);
  for(const table of tables) {
   const rows=db.prepare(`SELECT * FROM ${table}`).all();
   assert.equal(rows.length,previous[table].length);
   for(const [key,value] of Object.entries(previous[table][0])) assert.equal(rows[0][key],value,`${table}.${key} preserved`);
  }
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check,'ok');
 } finally {db.close();}
});

test('acceptance: 10000 records keep bounded pages, stable ordering, exact filters and no silent type loss',()=>{
 const db=fixture();
 try {
  const insert=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,severity,result_data) VALUES (?,?,?,?)');
  db.transaction(()=>{
   for(let i=0;i<10000;i++)insert.run(i%2?'ports':'web',i%5===0?'future_unknown_type':'vulnerability',i%3===0?'INFO':'high',JSON.stringify({finding:'fixture-'+i}));
  })();
  const pipeline=db.prepare('SELECT * FROM pipelines').get();
  const start=performance.now();
  let after=0;const seen=new Set();
  while(true) {
   const page=scanPage(db,pipeline,{limit:500,after});
   assert.ok(page.scan_records.length<=500);assert.equal(page.page.total,10000);
   for(const row of page.scan_records){assert.ok(row.id>after);assert.ok(!seen.has(row.id));seen.add(row.id);}
   if(!page.page.has_more)break;after=page.page.next_after;
  }
  assert.equal(seen.size,10000);
  assert.equal(scanPage(db,pipeline,{category:'other'}).page.total,2000);
  assert.equal(scanPage(db,pipeline,{scan_task_id:'ports'}).page.total,5000);
  console.log('acceptance 10000-record traversal milliseconds:',Math.round(performance.now()-start));
 } finally {db.close();}
});
