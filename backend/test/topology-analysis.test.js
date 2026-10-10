import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { getDb, closeDb } from '../src/db/connection.js';
let prompt = '';
await mock.module('../src/services/llmClient.js', { namedExports: {
  callLlm: async messages => {
    prompt = messages.map(m => m.content).join('\n');
    return { ok:true, content:'{}' };
  },
}});
const { analyzeScanResults } = await import('../src/services/scanAnalyzer.js');

test('LAN neighbors and raw discovery evidence never enter target attack analysis', async () => {
  const db = getDb(':memory:');
  db.exec(`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY, scan_task_id TEXT, target TEXT, scan_type TEXT,
    target_class TEXT, status TEXT, completed_at TEXT, started_at TEXT, created_at TEXT);
    CREATE TABLE scan_results (scan_task_id TEXT, result_type TEXT, result_data TEXT, severity TEXT,
    mitre_technique_id TEXT, source_tool TEXT);`);
  try {
    db.prepare('INSERT INTO scan_tasks (scan_task_id,target,scan_type,target_class,status,completed_at) VALUES (?,?,?,?,?,?)')
      .run('a','192.168.1.111','port_scan','host','COMPLETED',new Date().toISOString());
    const insert = db.prepare('INSERT INTO scan_results VALUES (?,?,?,?,?,?)');
    // More than the prompt limit: exclusions must happen before LIMIT.
    for (let i=0;i<40;i++) insert.run('a','lan_host_discovery',JSON.stringify({host:'192.168.1.30',service:'neighbor-only-marker'}),'info',null,'nmap');
    insert.run('a','scan_evidence',JSON.stringify({output:'neighbor-raw-marker'}),'info',null,'nmap');
    insert.run('a','lan_scope',JSON.stringify({cidr:'192.168.1.0/24'}),'info',null,'nmap');
    insert.run('a','open_port',JSON.stringify({host:'192.168.1.111',port:22,state:'open',service:'ssh-target-marker'}),'info',null,'nmap');
    const result = await analyzeScanResults(['a']);
    assert.equal(result.ok,true);
    assert.equal(result.data.findings_count,1);
    assert.ok(prompt.includes('ssh-target-marker'));
    assert.ok(!prompt.includes('neighbor-only-marker'));
    assert.ok(!prompt.includes('neighbor-raw-marker'));
    assert.ok(!prompt.includes('192.168.1.30'));
  } finally { closeDb(); }
});
