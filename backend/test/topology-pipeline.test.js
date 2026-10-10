import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { getDb, closeDb } from '../src/db/connection.js';
import { extractTopologyFromResults } from '../src/services/topologyBuilder.js';

const calls = [];
let rejectTrace = false;
const stdout = [
  'Nmap scan report for 198.51.100.10', 'Host is up.',
  '22/tcp open ssh OpenSSH 9.0', 'TRACEROUTE', 'HOP RTT ADDRESS',
  '1 0.1 ms 198.51.100.1', '2 0.2 ms 198.51.100.10',
].join('\n');
await mock.module('../src/tools/toolRunner.js', { namedExports: {
  runTool: async (tool, args) => {
    calls.push({tool,args});
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
const { executeScan } = await import('../src/services/scanExecutor.js');

test('original pipeline automatically collects topology without a second scan task or UI action', async () => {
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
    assert.ok(calls[0].args.includes('-sV'));
    assert.ok(calls[0].args.includes('--traceroute'));
    assert.deepEqual(calls[1].args,['--iflist']);
    const graph = extractTopologyFromResults(scans[0].target,db.prepare('SELECT * FROM scan_results').all());
    assert.ok(graph.nodes.some(n => n.deviceType === 'scanner'));
    assert.ok(graph.nodes.some(n => n.deviceType === 'router'));
    assert.ok(graph.edges.some(e => e.type === 'route'));
    assert.equal(db.prepare('SELECT status FROM pipeline_steps WHERE step_order=0').get().status,'completed', JSON.stringify(db.prepare('SELECT * FROM pipeline_steps').all()));

    // Capability failure falls back to the original scan and keeps the pipeline usable.
    calls.length = 0;
    rejectTrace = true;
    db.prepare("INSERT INTO scan_tasks (scan_task_id,target,scan_type,parameters) VALUES ('fallback','198.51.100.10','port_scan',?)")
      .run(JSON.stringify({discover_topology:true}));
    const fallback = await executeScan('fallback');
    assert.equal(fallback.status,'COMPLETED');
    assert.ok(calls[0].args.includes('--traceroute'));
    assert.ok(!calls[1].args.includes('--traceroute'));
    assert.ok(calls[1].args.includes('-sV'));
    assert.ok(db.prepare("SELECT * FROM scan_results WHERE scan_task_id='fallback' AND result_type='scan_warning'").get());
  } finally { closeDb(); }
});
