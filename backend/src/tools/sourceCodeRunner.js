import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {getEngine} from './containerEngine.js';
import {codeImage,parseCodeInvocation,normalizeCodeArtifact,codeHash} from '../services/verificationCodeArtifact.js';

// Backend-owned supervisor, passed as an argv value rather than a shell command.
// Existing tool images need no file installation or rebuild.
const WORKER_SOURCE=readFileSync(new URL('./sourceCodeWorker.py',import.meta.url),'utf8');

export function codeContainerArgs(name,language) {
  return ['run','--rm','--pull=never','--name',name,'--interactive','--network','none','--read-only',
    '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','512m','--cpus','1',
    '--user','65534:65534','--ulimit','nofile=128:128','--ulimit','core=0',
    '--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--entrypoint','python3',codeImage(language),'-I','-B','-c',WORKER_SOURCE];
}

// No host execution, bind mounts, inherited environment or arbitrary command line.
// Only the server-frozen artifact is sent to the fixed container entrypoint via stdin.
export async function runSourceCode(args,options={},deps={}) {
  const blocked=message=>({success:false,exitCode:-1,stdout:'',stderr:message,error:message,executionMode:'blocked',toolStarted:false,processStopped:true});
  if(options.signal?.aborted)return {...blocked('本地验证已取消'),aborted:true};
  let spec,artifact;
  try {
    spec=parseCodeInvocation(args);artifact=options.codeArtifact;
    if(!artifact || artifact.id!==spec.artifact_id || artifact.hash!==spec.artifact_hash || codeHash(normalizeCodeArtifact(artifact))!==spec.artifact_hash)
      return blocked('缺少与执行方案一致的冻结载荷');
  }catch(error){return blocked(error.message);}
  let engine;try{engine=await (deps.getEngine || getEngine)();}catch{return blocked('无法检测隔离执行环境');}
  if(!['docker','podman'].includes(engine))return blocked('本地载荷验证需要 Docker/Podman 及对应的现有工具镜像，不在宿主机执行');
  if(options.signal?.aborted)return {...blocked('本地验证已取消'),aborted:true};
  const name='rt-code-'+randomUUID();
  const input=JSON.stringify({artifact_id:artifact.id,artifact_hash:artifact.hash,...normalizeCodeArtifact(artifact),phase:spec.phase});
  const execute=deps.runContainer || ((engine,args,input,options)=>runContainer(engine,args,input,options,deps.spawn || spawn));
  return await execute(engine,codeContainerArgs(name,artifact.execution.language),input,{...options,name});
}

function removeContainer(engine,name,spawnProcess) {
  return new Promise(resolve=>{
    let done=false,inspecting;
    const finish=value=>{if(done)return;done=true;clearTimeout(timer);resolve(value);};
    const child=spawnProcess(engine,['rm','-f',name],{stdio:'ignore',shell:false});
    const timer=setTimeout(()=>{child.kill('SIGKILL');inspecting?.kill('SIGKILL');finish(false);},5000);
    child.on('error',()=>finish(false));child.on('close',()=>{
      if(done)return;
      // An absent container makes rm return nonzero on some engines. A successful
      // filtered listing with no matching name is the required stop evidence.
      let output='';
      const inspect=inspecting=spawnProcess(engine,['ps','-a','--filter','name='+name,'--format','{{.Names}}'],{shell:false,stdio:['ignore','pipe','ignore']});
      inspect.stdout.on('data',chunk=>{output+=chunk.toString();if(output.length>4096)inspect.kill('SIGKILL');});
      inspect.on('error',()=>finish(false));inspect.on('close',code=>finish(code===0 && output.length<=4096 && !output.split(/\s+/).includes(name)));
    });
  });
}
function runContainer(engine,args,input,options,spawnProcess) {
  return new Promise(resolve=>{
    const child=spawnProcess(engine,args,{shell:false,stdio:['pipe','pipe','pipe']});
    let stdout='',stderr='',bytes=0,aborted=false,timedOut=false,truncated=false,settled=false,stopping=null,hardTimer;
    const stop=()=>{
      if(stopping)return;
      stopping=removeContainer(engine,options.name,spawnProcess);
      child.kill('SIGTERM');
      hardTimer=setTimeout(()=>{child.kill('SIGKILL');finish(-1,false);},10000);
    };
    const onAbort=()=>{aborted=true;stop();};
    const timer=setTimeout(()=>{timedOut=true;stop();},Math.min(options.timeout || 60000,60000));
    const collect=(chunk,error)=>{
      bytes+=chunk.length;
      if(bytes>256*1024){truncated=true;stop();return;}
      if(error)stderr+=chunk.toString('utf8');else stdout+=chunk.toString('utf8');
    };
    const finish=async(code,closed=true)=>{
      if(settled)return;settled=true;clearTimeout(timer);clearTimeout(hardTimer);options.signal?.removeEventListener('abort',onAbort);
      // Even after a normal CLI exit, confirm no named container remains.
      const stopped=stopping?await stopping:await removeContainer(engine,options.name,spawnProcess);
      let observation;try{observation=JSON.parse(stdout);}catch{}
      const spec=JSON.parse(input);
      const valid=code===0 && !aborted && !timedOut && !truncated && observation?.format==='local-code-observation-v1'
        && observation.artifact_id===spec.artifact_id && observation.artifact_hash===spec.artifact_hash && observation.phase===spec.phase;
      const success=valid && observation.complete===true && observation.compile?.ok===true && observation.run?.started===true;
      resolve({success,exitCode:success?0:code || -1,stdout:valid?JSON.stringify(observation):'',stderr,
        executionMode:engine,toolStarted:valid && observation.run?.started===true,artifactConsumed:valid && observation.run?.started===true,
        processStopped:closed && stopped,aborted,timedOut,outputLimitExceeded:truncated,
        error:success?null:aborted?'本地验证已取消':timedOut?'本地验证超时':truncated?'本地验证输出超过限制':observation?.compile?.ok===false?'验证源码编译失败':observation?.run?.timed_out?'验证程序运行超时':'验证容器或程序未完整执行，请检查镜像与编译运行证据'});
    };
    child.stdout.on('data',c=>collect(c,false));child.stderr.on('data',c=>collect(c,true));
    child.stdin.on('error',()=>{});
    child.on('error',()=>{stderr='隔离容器启动失败';finish(-1);});
    child.on('close',code=>finish(code ?? -1));
    options.signal?.addEventListener('abort',onAbort,{once:true});
    if(options.signal?.aborted)onAbort();
    child.stdin.end(input);
  });
}
