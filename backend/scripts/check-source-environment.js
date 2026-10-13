import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {access,stat,writeFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {getEngine} from '../src/tools/containerEngine.js';
import {IMAGE_MAP} from '../src/tools/toolRunner.js';

// Inspect the same engine/account as the backend. Never pull/build images,
// contact a target/model, read credentials, or modify runtime data.
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
const engine=await getEngine(),architecture={x64:'amd64',arm64:'arm64'}[process.arch] || process.arch;
const report={checked_at:new Date().toISOString(),scope:'source collection and static tool environment; model and target execution require separate validation',
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
if(engine!=='host') {
  const image=await command(engine,['image','inspect','rt-sast-c:latest','--format','{{.Id}} {{.Architecture}} {{.Os}}']);
  report.sast_image=image.output || null;
  check('sast_image',image.passed,image.passed?image.output:'Missing rt-sast-c:latest; build containers/sast-c or load a matching offline image into '+engine);
  if(image.passed) {
    const actual=image.output.split(' ')[1];check('sast_architecture',actual===architecture,'rt-sast-c architecture must match '+architecture+' (found '+actual+')');
    for(const tool of ['cppcheck','flawfinder']) {
      const result=await command(engine,['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','rt-sast-c:latest',tool,'--version']);
      check(tool,result.passed,result.passed?result.output:tool+' cannot start in rt-sast-c');
    }
  }
  if(args.includes('--all-images')) for(const name of [...new Set(Object.values(IMAGE_MAP))].filter(name=>!['builtin','rt-sast-c'].includes(name))) {
    const result=await command(engine,['image','inspect',name+':latest','--format','{{.Id}} {{.Architecture}}']);
    report.optional_images.push({image:name+':latest',available:result.passed,identity:result.output || null});
  }
} else for(const tool of ['cppcheck','flawfinder']) {
  const result=await command(tool,['--version']);check(tool,result.passed,result.passed?result.output:'Host execution requires '+tool+' on PATH');
}
report.passed=report.missing.length===0;
const output=JSON.stringify(report,null,2)+'\n';
if(args.includes('--output')) await writeFile(resolve(option('--output')),output);
console.log(output);
if(!report.passed) process.exitCode=1;
