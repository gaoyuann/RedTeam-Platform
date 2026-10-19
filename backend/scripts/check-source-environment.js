import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {access,stat,writeFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {getEngine} from '../src/tools/containerEngine.js';
import {cscanConfig,createCscanClient} from '../src/services/cscanClient.js';
import {IMAGE_MAP} from '../src/tools/toolRunner.js';

// Read-only preflight. --api additionally authenticates to CScan without creating a Flow.
// Never pull/build images, contact a target/model, or modify runtime data.
const execute=promisify(execFile),args=process.argv.slice(2);
function option(name,fallback) {
  const index=args.indexOf(name);
  if(index<0) return fallback;
  if(!args[index+1] || args[index+1].startsWith('--')) throw new Error(name+' requires a value');
  return args[index+1];
}
const sourceKind=option('--source-kind','http');
if(!['http','local','ssh'].includes(sourceKind)) throw new Error('--source-kind must be http, local, or ssh');
const projectRoot=fileURLToPath(new URL('../../',import.meta.url));
const engine=args.includes('--all-images') ? await getEngine() : null,architecture={x64:'amd64',arm64:'arm64'}[process.arch] || process.arch;
const report={checked_at:new Date().toISOString(),scope:'CScan source input and report directories; --api checks authentication without submitting a scan',
  node:process.version,engine,architecture,source_kind:sourceKind,checks:[],optional_images:[],missing:[]};
async function command(binary,argv) {
  try {const result=await execute(binary,argv,{timeout:30000,maxBuffer:65536});return {passed:true,output:(result.stdout || result.stderr).trim().slice(0,250)};}
  catch {return {passed:false};}
}
function check(name,passed,message) {report.checks.push({name,passed,message});if(!passed) report.missing.push(message);}
check('node',Number(process.versions.node.split('.')[0])>=18,'Node.js 18 or later');
if(sourceKind==='local') {
  const result=await command('python3',['--version']);check('python',result.passed,result.passed?result.output:'Local source collection requires Python 3');
}
if(sourceKind==='ssh') {
  const result=await command('ssh',['-V']);check('ssh',result.passed,result.passed?result.output:'SSH source collection requires an SSH client');
  report.ssh_source_host_requirement='Read-only source account, verified host key, Python 3 on the source host; password-file authentication additionally needs sshpass';
}
for(const directory of ['data','data/output','data/source-scan/snapshots']) {
  let path=resolve(projectRoot,directory);
  try {
    // Collection creates missing descendants. Check their nearest existing
    // project directory without creating anything during the inspection.
    while(true) {
      try {if(!(await stat(path)).isDirectory()) throw new Error('Not a directory');break;}
      catch(error) {if(error.code!=='ENOENT' || path===projectRoot) throw error;path=dirname(path);}
    }
    await access(path,constants.W_OK | constants.X_OK);check(directory,true,directory+' has a writable destination');
  } catch {check(directory,false,directory+' cannot be created or written by the backend account');}
}
try {
  const config=cscanConfig();
  for(const [name,path,permissions] of [['cscan_sources',config.sourcesDir,constants.W_OK | constants.X_OK],
    ['cscan_reports',config.workDir,constants.R_OK | constants.X_OK]]) {
    try {await access(path,permissions);check(name,(await stat(path)).isDirectory(),name+' accessible');}
    catch {check(name,false,name+' inaccessible; configure the shared CScan workspace for the backend account');}
  }
  let credentials=!!config.token;
  if(!credentials && config.tokenFile) try {await access(config.tokenFile,constants.R_OK);credentials=true;} catch {}
  check('cscan_credentials',credentials,'CSCAN_TOKEN_FILE or CSCAN_API_TOKEN must be available to the backend');
  if(args.includes('--api')) {
    try {const client=await createCscanClient(config);await client.health();check('cscan_api',true,'CScan GraphQL authentication succeeded');}
    catch(error) {check('cscan_api',false,error.message);}
  }
} catch(error) {check('cscan_config',false,error.message);}
if(args.includes('--all-images') && engine!=='host') {
  for(const name of [...new Set(Object.values(IMAGE_MAP))].filter(name=>!['builtin','rt-sast-c'].includes(name))) {
    const result=await command(engine,['image','inspect',name+':latest','--format','{{.Id}} {{.Architecture}}']);
    report.optional_images.push({image:name+':latest',available:result.passed,identity:result.output || null});
  }
}
report.passed=report.missing.length===0;
const output=JSON.stringify(report,null,2)+'\n';
if(args.includes('--output')) await writeFile(resolve(option('--output')),output);
console.log(output);
if(!report.passed) process.exitCode=1;
