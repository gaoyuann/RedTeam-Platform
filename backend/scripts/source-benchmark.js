import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createSourceSnapshot} from '../src/services/sourceSnapshot.js';
import {sourceToolArgs} from '../src/services/sourceScanPolicy.js';
import {parseCppcheck,parseFlawfinder} from '../src/services/sourceToolParsers.js';
import {runTool} from '../src/tools/toolRunner.js';
import {scoreSourceBenchmark} from '../src/services/sourceBenchmark.js';
import {parseSourceDiagnostics} from '../src/services/sourceDiagnostics.js';

const directory=fileURLToPath(new URL('../test/fixtures/source/',import.meta.url));
const cases=JSON.parse(await readFile(join(directory,'benchmark.json'),'utf8'));
const temporary=await mkdtemp(join(tmpdir(),'rt-benchmark-')),execute=promisify(execFile);
const report={created_at:new Date().toISOString(),scope:'三个已知缺陷与三个修复对照，不代表真实项目精度',ai_evaluated:false,
  tools:{},diagnostics:[],errors:[]};
const rawResults=new Map();
try {
  const snapshot=await createSourceSnapshot({id:'benchmark',kind:'local',source_root:directory,architecture:process.arch},{snapshotRoot:temporary});
  report.source_versions=snapshot.files;
  for(const tool of ['cppcheck','flawfinder']) {
    const result=await runTool(tool,sourceToolArgs(tool),{sourceDir:snapshot.sourceDir,timeout:120000});
    rawResults.set(tool,result);
    if(!result.success) {report.errors.push({tool,error:result.error});continue;}
    const rows=(tool==='cppcheck'?parseCppcheck:parseFlawfinder)(result.stdout+'\n'+result.stderr);
    const findings=rows.map(row=>({...row.result_data,file:row.result_data.file.replace('/src/project/','').replace(snapshot.sourceDir+'/','')}));
    report.tools[tool]=scoreSourceBenchmark(findings,cases);
    report.tools[tool].findings=findings.map(({file,line,cwe,rule})=>({file,line,cwe,rule}));
  }
  if(process.argv.includes('--ai')) {
    // A temporary database requires explicit environment configuration, never the production DB.
    const {getDb,closeDb}=await import('../src/db/connection.js');
    const {auditSources}=await import('../src/services/sourceAudit.js');
    const db=getDb(':memory:');
    try {
      db.exec('CREATE TABLE system_config(category TEXT,config_key TEXT,config_value TEXT); CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT); CREATE TABLE source_audits(scan_task_id TEXT PRIMARY KEY,snapshot_id TEXT,connection_id TEXT,manifest TEXT,analysis TEXT,created_at TEXT);');
      await auditSources({scan_task_id:'benchmark',target:'http://127.0.0.1:9/'},{db,
        parameters:{source_url:'/fixture/',input_kind:'source',ai_batches:24},snapshot:async()=>snapshot,
        runTool:async tool=>rawResults.get(tool),
        parseResults:(type,output)=>(type==='source_scan_cppcheck'?parseCppcheck:parseFlawfinder)(output)});
      const coverage=JSON.parse(db.prepare('SELECT analysis FROM source_audits').get().analysis);
      const findings=db.prepare("SELECT result_data FROM scan_results WHERE result_type='source_finding'").all()
        .map(row=>JSON.parse(row.result_data)).filter(finding=>finding.tools.includes('source-ai'));
      report.ai={primary:scoreSourceBenchmark(findings,cases),after_counter_review:scoreSourceBenchmark(findings.filter(finding=>finding.counter_review?.verdict!=='unlikely'),cases),
        coverage,conclusion:'这是模型候选筛选指标，未复核/条件未知的候选仍算告警，不能据此声称已验证漏洞'};
      report.ai_evaluated=coverage.ai_complete;
      if(!coverage.ai_complete) report.errors.push({tool:'source-ai',error:'模型审阅或反证复核未完整完成，AI指标不能用作完整测评'});
    } finally {closeDb();}
  }
  if(process.argv.includes('--diagnostics')) {
    // Only these checked-in fixtures and fixed wrappers are compiled. Never uploaded source.
    const calls={'bounds-vulnerable':'overflow()', 'bounds-fixed':'copy_input(buffer,sizeof(buffer),"ok")',
      'null-vulnerable':'null_access()', 'null-fixed':'read_value(0)',
      'lifetime-vulnerable':'expired_value()', 'lifetime-fixed':'valid_value()'};
    for(const item of cases) {
      const main=join(temporary,'main'+(item.file.endsWith('.cpp')?'.cpp':'.c')),binary=join(temporary,'fixture-run');
      await writeFile(main,'#include "'+join(snapshot.sourceDir,item.file)+'"\nint main(void) { char buffer[16]; (void)'+calls[item.id]+'; return 0; }\n');
      try {
        await execute(item.file.endsWith('.cpp')?'g++':'gcc',['-g','-O0','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-no-pie',main,'-o',binary],{timeout:30000,maxBuffer:65536});
      } catch {report.errors.push({case:item.id,error:'诊断样例编译失败，请检查 GCC/G++ 和 sanitizer 运行库'});continue;}
      let output='',failed=false;
      try {const result=await execute(binary,[],{timeout:5000,maxBuffer:65536,env:{...process.env,ASAN_OPTIONS:'detect_leaks=0:abort_on_error=0:disable_coredump=1',UBSAN_OPTIONS:'print_stacktrace=1:halt_on_error=1'}});output=result.stdout+'\n'+result.stderr;}
      catch(error) {failed=true;output=String(error.stdout || '')+'\n'+String(error.stderr || '');}
      const diagnostics=parseSourceDiagnostics(output,snapshot.files);
      const expected={bounds:'stack-buffer-overflow',null:'null-pointer',lifetime:'heap-use-after-free'}[item.pair];
      const passed=item.vulnerable ? failed && diagnostics.some(d=>d.type===expected && d.locations.some(loc=>loc.file===item.file)) : !failed && diagnostics.length===0;
      report.diagnostics.push({case:item.id,passed,expected:item.vulnerable?expected:'no_diagnostic',diagnostics});
      if(!passed) report.errors.push({case:item.id,error:'运行诊断与样例预期不一致'});
    }
  }
  const argument=process.argv.indexOf('--output');
  if(argument>=0) {if(!process.argv[argument+1]) throw new Error('--output 需要文件路径');await writeFile(resolve(process.argv[argument+1]),JSON.stringify(report,null,2)+'\n');}
  console.log(JSON.stringify(report,null,2));
  if(report.errors.length) process.exitCode=1;
} finally {await rm(temporary,{recursive:true,force:true});}
