import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { getDb, closeDb } from '../src/db/connection.js';
import { extractTopologyFromResults } from '../src/services/topologyBuilder.js';

const calls = [];
let rejectTrace = false;
let failScan = false;
let failLan = false;
let abortPhase = '';
let abortSignalReceived = false;
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
      stderr:failLan ? 'timeout' : '',stdout:'Nmap scan report for 198.51.100.30\nHost is up (arp-response).'};
    if (failScan && !args.includes('--iflist'))
      return {success:false,exitCode:1,stderr:'target probe failed',stdout:''};
    if (rejectTrace && args.includes('--traceroute'))
      return {success:false,exitCode:1,stderr:'traceroute requires root privileges',stdout:''};
    return {success:true,exitCode:0,stderr:'',executionMode:'test',stdout:args.includes('--iflist')
      ? 'INTERFACES\neth0 (eth0) 198.51.100.5/24 ethernet up 1500\nROUTES\n198.51.100.0/24 eth0 0'
      : stdout};
  },
}});
await mock.module('../src/services/scanAnalyzer.js', { namedExports: {
  analyzeScanResults: async () => { throw new Error('test boundary: scan complete; no LLM call'); },
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
    assert.equal(fallback.status,'COMPLETED');
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
