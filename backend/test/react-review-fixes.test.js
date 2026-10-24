import test from 'node:test';import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {executionTargetsOverlap} from '../src/services/taskScope.js';
import {scanAgentBusy,defaultScanAgent,validateScanAgentMode} from '../src/services/scanAgentConfig.js';
import {normalizeAnalysisEvidence} from '../src/services/scanAnalyzer.js';
test('execution locks cover CIDR overlap both ways and stopped-unknown records',()=>{
 for(const [a,b,want] of [['192.0.2.0/24','http://192.0.2.8/',true],['192.0.2.0/24','192.0.2.128/25',true],['0.0.0.0/0','192.0.2.8',true],['192.0.2.8/32','192.0.2.9',false],['192.0.2.0/24','192.0.3.0/24',false],['https://EXAMPLE.test/a','http://example.test:8080/b',true]]){
  assert.equal(executionTargetsOverlap(a,b),want);assert.equal(executionTargetsOverlap(b,a),want);
 }
 const db=new Database(':memory:');try{
  db.exec("CREATE TABLE pipelines(pipeline_id TEXT,target TEXT,status TEXT);CREATE TABLE scan_tasks(scan_task_id TEXT,target TEXT);CREATE TABLE scan_tool_runs(scan_task_id TEXT,state TEXT,outcome TEXT);INSERT INTO pipelines VALUES ('p','192.0.2.0/24','running');");
  assert.equal(scanAgentBusy(db,'http://192.0.2.8/'),true);assert.equal(scanAgentBusy(db,'192.0.3.8'),false);assert.equal(scanAgentBusy(db,'192.0.2.8','p'),false);
  db.exec("UPDATE pipelines SET status='failed';INSERT INTO scan_tasks VALUES ('s','192.0.2.8');INSERT INTO scan_tool_runs VALUES ('s','failed','{\"stopped\":false}');");
  assert.equal(scanAgentBusy(db,'192.0.2.0/24'),true);db.exec("UPDATE scan_tool_runs SET outcome='{\"stopped\":true}'");assert.equal(scanAgentBusy(db,'192.0.2.0/24'),false);
  db.exec("UPDATE scan_tool_runs SET state='running'");assert.equal(scanAgentBusy(db,'192.0.2.0/24'),true);
 }finally{db.close();}
});
test('mode normalization removes conflicting source marker and start validator rejects it',()=>{
 const bad={test_type:'source',source_path:'/src/demo',scan_orchestrator:{version:1,mode:'react'}};
 assert.throws(()=>validateScanAgentMode(bad,'http://fixture.test/'),/冲突/);
 const fixed=defaultScanAgent(bad,'http://fixture.test/');assert.equal(fixed.scan_orchestrator,undefined);assert.doesNotThrow(()=>validateScanAgentMode(fixed,'http://fixture.test/'));
});
test('analysis aliases share evidence validation and invalid types produce controlled errors',()=>{
 for(const key of ['risk_assessment','riskAssessment','风险评估']){
  const r=normalizeAnalysisEvidence({[key]:[{description:'keep',evidence_ids:[7,7,99]},{description:'drop',evidence_ids:[88]}]},[7]);
  assert.equal(r.ok,true);assert.equal(r.data.risk_assessment.length,1);assert.deepEqual(r.data.risk_assessment[0].evidence_ids,[7]);assert.equal(r.data.risk_assessment[0].verification_status,'unverified');assert.ok(r.warnings.some(x=>/剔除 1/.test(x)));
 }
 for(const value of [{},'text',3,[null],['text']])assert.equal(normalizeAnalysisEvidence({risk_assessment:value},[7]).ok,false);
 for(const value of [null,[],42])assert.equal(normalizeAnalysisEvidence(value,[7]).ok,false);
 assert.deepEqual(normalizeAnalysisEvidence({risk_assessment:[]},[7]).data.risk_assessment,[]);
});
