import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { getDb, closeDb } from '../src/db/connection.js';
import { extractTopologyFromResults } from '../src/services/topologyBuilder.js';
import {pipelineTopology} from '../src/services/topologyProjection.js';
import { runMigrations } from '../src/db/migrate.js';
import { fileURLToPath } from 'node:url';

const calls = [];
let rejectTrace = false;
let failScan = false;
let failLan = false;
let abortPhase = '';
let abortSignalReceived = false;
let failSource = false;
const defaultContext = 'INTERFACES\neth0 (eth0) 198.51.100.5/24 ethernet up 1500\nROUTES\n198.51.100.0/24 eth0 0';
let contextOutput = defaultContext;
let lanOutput = 'Nmap scan report for 198.51.100.30\nHost is up (arp-response).';
const stdout = [
  'Nmap scan report for 198.51.100.10', 'Host is up.',
  '22/tcp open ssh OpenSSH 9.0', 'TRACEROUTE', 'HOP RTT ADDRESS',
  '1 0.1 ms 198.51.100.1', '2 0.2 ms 198.51.100.10',
].join('\n');
await mock.module('../src/tools/toolRunner.js', { namedExports: {
  runTool: async (tool, args, options = {}) => {
    calls.push({tool,args});
    const phase = args.includes('--iflist') ? 'context' : args.includes('-sn') ? 'lan' : 'target';
    if (phase === abortPhase) {
      requestScanAbort('cancelled-' + phase);
      return new Promise(resolve => options.signal?.addEventListener('abort', () => {
        abortSignalReceived = true;
        resolve({success:false,exitCode:-2,executionMode:'aborted',stdout:'',stderr:'cancelled'});
      }, {once:true}));
    }
    if (args.includes('-sn')) return {success:!failLan,timedOut:failLan,exitCode:failLan ? 1 : 0,executionMode:'test',
      stderr:failLan ? 'timeout' : '',stdout:lanOutput};
    if (failScan && !args.includes('--iflist'))
      return {success:false,exitCode:1,stderr:'target probe failed',stdout:''};
    if (rejectTrace && args.includes('--traceroute'))
      return {success:false,exitCode:1,stderr:'traceroute requires root privileges',stdout:''};
    return {success:true,exitCode:0,stderr:'',executionMode:'test',stdout:args.includes('--iflist')
      ? contextOutput
      : stdout};
  },
}});
await mock.module('../src/services/scanAnalyzer.js', { namedExports: {
  analyzeScanResults: async () => { throw new Error('test boundary: scan complete; no LLM call'); },
}});
await mock.module('../src/services/sourceAudit.js', {namedExports:{
  auditSources:async(task,{db})=>{
    db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'source_finding',?)")
      .run(task.scan_task_id,JSON.stringify({title:'Fixture static candidate',file:'input.c'}));
    return {count:1,outcomes:[{tool_id:'fixture-source',success:!failSource,error:failSource?'source tool unavailable':null}]};
  },
}});
const { runPipeline } = await import('../src/services/pipelineEngine.js');
const { executeScan, requestScanAbort } = await import('../src/services/scanExecutor.js');

test('original pipeline automatically collects topology without a second scan task or UI action', async t => {
  const db = getDb(':memory:');
  db.exec([
    'CREATE TABLE pipelines (pipeline_id TEXT, target TEXT, status TEXT, config TEXT, created_by TEXT, updated_at TEXT, error_message TEXT, scan_task_id TEXT, result TEXT, analysis_result TEXT)',
    'CREATE TABLE pipeline_steps (id INTEGER PRIMARY KEY, pipeline_id TEXT, step_order INTEGER, step_type TEXT, status TEXT, started_at TEXT, completed_at TEXT, input_data TEXT, output_data TEXT, error_message TEXT)',
    "CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY, scan_task_id TEXT, target TEXT, scan_type TEXT, target_class TEXT, parameters TEXT, created_by TEXT, created_at TEXT, status TEXT DEFAULT 'PENDING', started_at TEXT, completed_at TEXT, error_message TEXT, target_profile TEXT)",
    'CREATE TABLE scan_results (id INTEGER PRIMARY KEY, scan_task_id TEXT, result_type TEXT, result_data TEXT, severity TEXT, confidence TEXT, mitre_technique_id TEXT, source_tool TEXT, captured_at TEXT)',
  ].join(';'));
  try {
    db.prepare('INSERT INTO pipelines (pipeline_id,target,status,config,created_by) VALUES (?,?,?,?,?)')
      .run('auto','198.51.100.10','created','{}','alice');
    await runPipeline('auto');
    const scans = db.prepare('SELECT * FROM scan_tasks').all();
    assert.equal(scans.length,1, 'the existing port scan is retained, no additional task is created');
    assert.equal(scans[0].scan_type,'port_scan');
    assert.equal(scans[0].status,'COMPLETED');
    assert.equal(JSON.parse(scans[0].parameters).discover_topology,true);
    assert.ok(calls[1].args.includes('-sV'));
    assert.ok(calls[1].args.includes('--traceroute'));
    assert.deepEqual(calls[0].args,['--iflist']);
    const graph = extractTopologyFromResults(scans[0].target,db.prepare('SELECT * FROM scan_results').all());
    assert.ok(graph.nodes.some(n => n.deviceType === 'scanner'));
    assert.ok(graph.nodes.some(n => n.deviceType === 'router'));
    assert.equal(graph.edges.filter(e => e.type === 'route').length,2);
    assert.ok(graph.edges.some(e => e.sourceId === 'host-198.51.100.5' && e.targetId === 'host-198.51.100.1'));
    const evidence = JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_evidence'").get().result_data);
    assert.ok(evidence.args.includes('--traceroute'));
    assert.equal(evidence.args.at(-1),'198.51.100.10', 'the target service scan stays scoped to the original target');
    assert.equal(evidence.output, stdout);
    const lanCall = calls.find(c => c.args.includes('-sn'));
    assert.equal(lanCall.args.at(-1),'198.51.100.0/24');
    assert.ok(!lanCall.args.includes('-sV'));
    assert.equal(lanCall.args[lanCall.args.indexOf('-e')+1],'eth0');
    assert.ok(graph.nodes.some(n => n.ip === '198.51.100.30' && !n.tags.includes('target')));
    assert.ok(graph.nodes.some(n => n.deviceType === 'network_segment'));
    assert.ok(graph.edges.some(e => e.type === 'virtual-link'));
    assert.equal(db.prepare('SELECT status FROM pipeline_steps WHERE step_order=0').get().status,'completed', JSON.stringify(db.prepare('SELECT * FROM pipeline_steps').all()));

    // Capability failure falls back to the original scan and keeps the pipeline usable.
    calls.length = 0;
    rejectTrace = true;
    failLan = true;
    db.prepare("INSERT INTO scan_tasks (scan_task_id,target,scan_type,parameters) VALUES ('fallback','198.51.100.10','port_scan',?)")
      .run(JSON.stringify({discover_topology:true}));
    const fallback = await executeScan('fallback');
    assert.equal(fallback.status,'PARTIAL', 'fallback retains incomplete route discovery instead of claiming all checks completed');
    assert.ok(db.prepare("SELECT * FROM scan_results WHERE scan_task_id='fallback' AND result_type='scan_error'").get(), 'failed attempt remains traceable');
    assert.ok(db.prepare("SELECT * FROM scan_results WHERE scan_task_id='fallback' AND result_type='scan_warning'").all()
      .some(r => JSON.parse(r.result_data).phase === 'lan-discovery'));
    assert.ok(db.prepare("SELECT * FROM scan_results WHERE scan_task_id='fallback' AND result_type='lan_host_discovery'").get());
    assert.ok(calls[1].args.includes('--traceroute'));
    assert.ok(!calls[2].args.includes('--traceroute'));
    assert.ok(calls[2].args.includes('-sV'));
    assert.ok(db.prepare("SELECT * FROM scan_results WHERE scan_task_id='fallback' AND result_type='scan_warning'").get());
    // Source metadata survives a failed probe; no fabricated path is displayed.
    calls.length = 0;
    failScan = true;
    db.prepare("INSERT INTO scan_tasks (scan_task_id,target,scan_type,parameters) VALUES ('failed','198.51.100.10','port_scan',?)")
      .run(JSON.stringify({discover_topology:true}));
    const failed = await executeScan('failed');
    assert.equal(failed.status,'FAILED');
    const failedGraph = extractTopologyFromResults('198.51.100.10',
      db.prepare("SELECT * FROM scan_results WHERE scan_task_id='failed'").all());
    assert.ok(failedGraph.nodes.some(n => n.deviceType === 'scanner' && n.tags.includes('server')));
    assert.equal(failedGraph.nodes.find(n => n.ip === '198.51.100.10').status,'unknown');
    assert.deepEqual(failedGraph.edges,[]);
    failScan = rejectTrace = failLan = false;
    for (const phase of ['context','target','lan']) await t.test('cancellation stops the tool during ' + phase, async () => {
      calls.length = 0;
      abortPhase = phase;
      abortSignalReceived = false;
      const id = 'cancelled-' + phase;
      db.prepare('INSERT INTO scan_tasks (scan_task_id,target,scan_type,parameters) VALUES (?,?,?,?)')
        .run(id,'198.51.100.10','port_scan',JSON.stringify({discover_topology:true}));
      const cancelled = await executeScan(id);
      assert.equal(cancelled.status,'CANCELLED');
      assert.equal(abortSignalReceived,true,'the running tool must receive an abort signal, not just change task status');
      assert.equal(calls.length,{context:1,target:2,lan:3}[phase]);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM scan_results WHERE scan_task_id=? AND result_type='lan_scope'").get(id).n,0);
      abortPhase = '';
    });
  } finally { closeDb(); }
});

test('source input without runtime still collects network topology and preserves either side on failure',async t=>{
  for(const failed of ['none','source','network']) await t.test(failed,async()=>{
    const db=getDb(':memory:');
    db.exec([
      'CREATE TABLE pipelines (pipeline_id TEXT, target TEXT, status TEXT, config TEXT, created_by TEXT, updated_at TEXT, error_message TEXT, scan_task_id TEXT, result TEXT, analysis_result TEXT)',
      'CREATE TABLE pipeline_steps (id INTEGER PRIMARY KEY, pipeline_id TEXT, step_order INTEGER, step_type TEXT, status TEXT, started_at TEXT, completed_at TEXT, input_data TEXT, output_data TEXT, error_message TEXT)',
      "CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY, scan_task_id TEXT, target TEXT, scan_type TEXT, target_class TEXT, parameters TEXT, created_by TEXT, created_at TEXT, status TEXT DEFAULT 'PENDING', started_at TEXT, completed_at TEXT, error_message TEXT, target_profile TEXT)",
      'CREATE TABLE scan_results (id INTEGER PRIMARY KEY, scan_task_id TEXT, result_type TEXT, result_data TEXT, severity TEXT, confidence TEXT, mitre_technique_id TEXT, source_tool TEXT, captured_at TEXT)',
      'CREATE TABLE source_audits (scan_task_id TEXT)',
    ].join(';'));
    try {
      calls.length=0;failScan=failed==='network';failSource=failed==='source';
      const target='http://198.51.100.10:8089/source/';
      db.prepare('INSERT INTO pipelines(pipeline_id,target,status,config,created_by) VALUES (?,?,?,?,?)')
        .run('static-network',target,'created',JSON.stringify({scan_mode:'source_assisted',input_kind:'source',source_url:target}),'alice');
      await runPipeline('static-network');
      const scans=db.prepare('SELECT * FROM scan_tasks ORDER BY id').all();
      assert.deepEqual(scans.map(scan=>scan.scan_type),['source_scan','port_scan']);
      assert.equal(scans[0].status,failed==='source'?'FAILED':'COMPLETED');
      assert.equal(scans[1].status,failed==='network'?'FAILED':'COMPLETED');
      assert.equal(db.prepare('SELECT status FROM pipeline_steps WHERE step_order=0').get().status,'completed');
      assert.equal(JSON.parse(scans[1].parameters).pipeline_id,'static-network');
      const probe=calls.find(call=>call.args.includes('-sV'));
      assert.equal(probe.args.at(-1),'198.51.100.10');
      assert.equal(probe.args[probe.args.indexOf('-p')+1],'8089');
      assert.ok(probe.args.includes('--traceroute'));
      assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='source_finding'").get().n,1);
      const graph=pipelineTopology(db,db.prepare("SELECT * FROM pipelines WHERE pipeline_id='static-network'").get());
      assert.deepEqual(graph.risks,[]);assert.equal(graph.edges.some(edge=>edge.type==='application-request'),false);
      if(failed!=='network') {
        assert.ok(db.prepare("SELECT * FROM scan_results WHERE result_type='host_discovery'").get());
        assert.equal(graph.edges.filter(edge=>edge.type==='route').length,2);
        assert.equal(graph.nodes.find(node=>node.ip==='198.51.100.10').status,'up');
      } else {
        assert.equal(graph.nodes.find(node=>node.ip==='198.51.100.10').status,'unknown');
        assert.equal(graph.edges.filter(edge=>edge.type==='route').length,0);
      }
    } finally {failScan=failSource=false;closeDb();}
  });
});

test('scoped single IP tests discover LAN neighbors exclusively for topology', async t => {
  for (const scenario of ['complete','timeout','routed','unknown-context']) await t.test(scenario, async () => {
    const db = getDb(':memory:');
    await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
    db.prepare("INSERT INTO users(username,password,role) VALUES ('alice','fixture','user')").run();
    const config = {task_scope:{includes:['198.51.100.10'], excludes:[
      '198.51.100.40', 'http://198.51.100.41:8080/private/', '198.51.100.48/29',
    ], execution_location:'scanner', discovery_budget:2}};
    db.prepare("INSERT INTO pipelines(pipeline_id,target,status,config,created_by) VALUES ('single','198.51.100.10','created',?,'alice')")
      .run(JSON.stringify(config));
    calls.length = 0;
    failLan = scenario === 'timeout';
    contextOutput = scenario === 'routed'
      ? 'INTERFACES\neth0 (eth0) 203.0.113.5/24 ethernet up 1500\nROUTES\n0.0.0.0/0 eth0 0 203.0.113.1'
      : scenario === 'unknown-context' ? ''
        : 'INTERFACES\neth0 (eth0) 198.51.100.5/26 ethernet up 1500\nROUTES\n198.51.100.0/26 eth0 0';
    lanOutput = ['198.51.100.30','198.51.100.40','198.51.100.41','198.51.100.50','198.51.100.200']
      .map(host => `Nmap scan report for ${host}\nHost is up (arp-response).\n9999/tcp open http neighbor-only-marker`).join('\n');
    try {
      await runPipeline('single');
      const scans = db.prepare("SELECT * FROM scan_tasks WHERE pipeline_id='single'").all();
      assert.equal(scans.length, 1, 'neighbor discovery never queues another scan');
      const scan = scans[0];
      assert.equal(scan.status, 'COMPLETED', 'auxiliary discovery failure does not fail the target test');
      assert.equal(db.prepare("SELECT status FROM pipeline_steps WHERE pipeline_id='single' AND step_order=0").get().status, 'completed');
      const targetCall = calls.find(call => call.args.includes('-sV'));
      assert.equal(targetCall.args.at(-1), '198.51.100.10');
      const lanCall = calls.find(call => call.args.includes('-sn'));
      const rows = db.prepare('SELECT * FROM scan_results WHERE scan_task_id=?').all(scan.scan_task_id);
      const neighbors = rows.filter(row => row.result_type === 'lan_host_discovery');
      const pipeline = db.prepare("SELECT * FROM pipelines WHERE pipeline_id='single'").get();
      assert.deepEqual(JSON.parse(pipeline.config), config, 'the stored task scope is unchanged');
      const graph = pipelineTopology(db, pipeline);
      if (['complete','timeout'].includes(scenario)) {
        assert.equal(lanCall.args.at(-1), '198.51.100.0/26', 'use the real mask instead of guessing /24');
        assert.equal(lanCall.args[lanCall.args.indexOf('--exclude')+1], '198.51.100.40,198.51.100.41,198.51.100.48/29');
        assert.equal(lanCall.args.includes('-sV'), false);
        assert.deepEqual(neighbors.map(row => JSON.parse(row.result_data).host), ['198.51.100.30']);
        const scope = JSON.parse(rows.find(row => row.result_type === 'lan_scope').result_data);
        assert.equal(scope.purpose, 'topology_only');
        assert.equal(scope.complete, scenario === 'complete');
        const neighbor = graph.nodes.find(node => node.ip === '198.51.100.30');
        assert.ok(neighbor);
        assert.deepEqual(neighbor.services, []);
        assert.deepEqual(neighbor.checks, []);
        assert.deepEqual(neighbor.findings, []);
        assert.equal(neighbor.assetId, null);
        assert.equal(neighbor.scan.eligible, false);
        assert.match(neighbor.scan.reason, /超出任务范围/);
        assert.equal(neighbor.tags.includes('target'), false);
        assert.ok(neighbor.provenance.sources.some(source => source.result_type === 'lan_host_discovery'));
        const run = db.prepare('SELECT * FROM scan_tool_runs WHERE tool_run_id=?').get(neighbors[0].tool_run_id);
        assert.equal(run.state, scenario === 'complete' ? 'completed' : 'timed_out');
        assert.equal(JSON.parse(run.diagnostics).persisted_records, rows.filter(row => row.tool_run_id === run.tool_run_id).length);
        if (scenario === 'timeout') assert.ok(rows.some(row => row.result_type === 'scan_warning'
          && JSON.parse(row.result_data).phase === 'lan-discovery'));
      } else {
        assert.equal(lanCall, undefined);
        assert.deepEqual(neighbors, []);
        assert.ok(rows.some(row => row.result_type === 'scan_warning' && JSON.parse(row.result_data).phase === 'lan-discovery'));
      }
      assert.equal(db.prepare("SELECT COUNT(*) n FROM task_assets WHERE pipeline_id='single' AND host='198.51.100.30'").get().n, 0);
      assert.equal(db.prepare("SELECT COUNT(*) n FROM task_checks WHERE pipeline_id='single' AND target LIKE '%198.51.100.30%'").get().n, 0);
      assert.equal(rows.some(row => row.result_type === 'open_port' && JSON.parse(row.result_data).host === '198.51.100.30'), false);
      assert.equal(scan.target_profile.includes('neighbor-only-marker'), false);
      assert.equal(scan.target_profile.includes('198.51.100.30'), false);
      const count = calls.length;
      assert.equal((await executeScan(scan.scan_task_id)).ok, false, 'finished scans cannot be repeated');
      assert.equal(calls.length, count);
    } finally {
      failLan = false; contextOutput = defaultContext;
      lanOutput = 'Nmap scan report for 198.51.100.30\nHost is up (arp-response).';
      closeDb();
    }
  });
});
