import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import express from 'express';
import { getDb, closeDb } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';

const calls=[];
await mock.module('../src/tools/toolRunner.js',{namedExports:{runTool:async(tool,args)=>{
  calls.push({tool,args});
  if(args.includes('--iflist')) return {success:false,exitCode:1,stdout:'',stderr:'fixture has no interface list'};
  if(tool==='nmap') return {success:true,exitCode:0,stdout:[
    'Nmap scan report for 192.0.2.2','Host is up.',
    '8080/tcp open http Apache','22/tcp open ssh OpenSSH',
  ].join('\n'),stderr:''};
  if(tool==='arjun') return {success:true,exitCode:0,stdout:'[+] Parameter: id found in URL query',stderr:''};
  if(tool==='ffuf') return {success:true,exitCode:0,stdout:JSON.stringify({url:'http://192.0.2.2:8080/api/users',status:200}),stderr:''};
  if(tool==='httpx') return {success:true,exitCode:0,stdout:'http://192.0.2.2:8080/ [200] [fixture]',stderr:''};
  return {success:true,exitCode:0,stdout:'',stderr:''};
}}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async()=>{
  throw new Error('fixture stops before model analysis');
}}});
const {runPipeline}=await import('../src/services/pipelineEngine.js');
const {scanPage}=await import('../src/services/scanResultQuery.js');
const {default:taskResultsRoutes}=await import('../src/routes/taskResults.js');

test('parent run plans real HTTP service, records unsupported SSH and includes every child in F04 pages',async()=>{
  const db=getDb(':memory:');
  const originalFetch=globalThis.fetch;
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare('INSERT OR IGNORE INTO users(username,password,role) VALUES (?,?,?)').run('coverage-fixture','fixture','user');
  const config={task_scope:{version:1,includes:['192.0.2.0/28'],excludes:[],execution_location:'scanner',
    environment_ref:null,auth_config_ref:null,discovery_budget:1}};
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,config,created_by) VALUES ('coverage-fixture','192.0.2.0/28','created',?,'coverage-fixture')")
    .run(JSON.stringify(config));
  globalThis.fetch=async url=>{
    assert.equal(String(url),'http://192.0.2.2:8080/');
    return new Response('<title>fixture</title><a href="/help">help</a>',{status:200});
  };
  try {
    await runPipeline('coverage-fixture');
    const scans=db.prepare('SELECT scan_task_id,target,scan_type,status FROM scan_tasks WHERE pipeline_id=? ORDER BY id').all('coverage-fixture');
    assert.ok(scans.some(row=>row.scan_type==='port_scan' && row.status==='COMPLETED'));
    assert.ok(scans.some(row=>row.scan_type==='app_discovery' && row.target==='http://192.0.2.2:8080/'));
    assert.ok(scans.some(row=>row.scan_type==='web_scan'));
    assert.ok(scans.some(row=>row.scan_type==='api_fuzz'));
    assert.ok(scans.some(row=>row.target==='http://192.0.2.2:8080/help'));
    assert.equal(scans.filter(row=>row.target==='http://192.0.2.2:8080/help').length,1,'new entry obeys budget');
    assert.equal(calls.some(call=>call.tool==='nikto'),true);
    const pipeline=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get('coverage-fixture');
    const page=scanPage(db,pipeline,{limit:500});
    assert.equal(page.scan_records.length,db.prepare(`SELECT COUNT(*) n FROM scan_results WHERE scan_task_id IN
      (SELECT scan_task_id FROM scan_tasks WHERE pipeline_id=?)`).get('coverage-fixture').n);
    assert.equal(page.scan_coverage.counts.services,2);
    assert.ok(page.scan_coverage.checks.some(row=>row.state==='unsupported' && row.check_type==='service_security'));
    assert.ok(page.scan_coverage.checks.some(row=>row.state==='missing_condition' && row.check_type==='authenticated_roles'));
    assert.ok(page.scan_summary.unfinished_check_count>0,'saved results must still disclose unfinished coverage');
    db.prepare('INSERT OR IGNORE INTO users(username,password,role) VALUES (?,?,?)').run('coverage-other','fixture','user');
    const app=express();
    app.use((req,res,next)=>{req.user={sub:req.headers['x-user'] || 'coverage-fixture',role:'user'};next();});
    app.use('/pipelines/:id/results',taskResultsRoutes(db));
    const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    try {
      const base=`http://127.0.0.1:${server.address().port}/pipelines/coverage-fixture/results/coverage`;
      assert.equal((await originalFetch(base,{headers:{'x-user':'coverage-other'}})).status,403);
      const first=await originalFetch(`${base}?kind=checks&limit=2`);
      assert.equal(first.status,200);
      const body=(await first.json()).data;
      assert.equal(body.rows.length,2);
      assert.equal(body.page.total,page.scan_coverage.counts.checks);
      assert.equal((await originalFetch(`${base}?kind=checks&limit=501`)).status,400);
    } finally {await new Promise(resolve=>server.close(resolve));}
  } finally {globalThis.fetch=originalFetch;closeDb();}
});
