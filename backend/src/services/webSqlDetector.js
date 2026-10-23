import {mkdtemp,rm,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,basename} from 'node:path';
import {runTool} from '../tools/toolRunner.js';

export function sqlDetectionArgs(url,parameter,cookie,authorization='',request={}) {
  const u=new URL(url);
  if(!/^[\w.-]{1,80}$/.test(parameter)||(request.method!=='POST'&&(!u.searchParams.has(parameter)||u.searchParams.getAll(parameter).length!==1)))throw new Error('SQL 检测参数无效');
  if(request.method==='POST' && (!['form','json'].includes(request.encoding)||typeof request.body!=='string'||/[\r\n\0]/.test(request.body)))throw Error('POST 检测模板无效');
  const headers=[...(authorization?['Authorization: '+authorization]:[]),...(request.method==='POST'?['Content-Type: '+(request.encoding==='json'?'application/json':'application/x-www-form-urlencoded')]:[])];
  return ['-u',u.href,'-p',parameter,'--batch','--level=1','--risk=1','--technique=BEU','--threads=1',
    '--timeout=10','--retries=0','--ignore-redirects','--answers=refresh=N,redirect=N,follow=N,extend=N','--ignore-proxy','--drop-set-cookie','--skip-waf','--disable-coloring',
    '--flush-session','--fresh-queries','--output-dir=/tmp/redteam-private/output',
    ...(cookie?['--cookie',cookie]:[]),...(headers.length?['--headers',headers.join('\n')]:[]),...(request.method==='POST'?['--method=POST','--data',request.body]:[])];
}
export function sqlDetectionResult(result,parameter,request={}) {
  const text=String(result.stdout||'').replace(/\x1b\[[0-9;]*m/g,'');
  const techniques=[];
  for(const part of text.split(/^Parameter:\s*/m).slice(1)) {
    const head=part.split(/\r?\n/)[0].trim();const expected=request.method==='POST'?(request.encoding==='json'?[`JSON ${parameter} ((custom) POST)`,`${parameter} (POST)`]:[`${parameter} (POST)`]):[`${parameter} (GET)`];if(!expected.includes(head))continue;
    for(const m of part.matchAll(/^\s*Type:\s*([^\r\n]+)\r?\n\s*Title:\s*([^\r\n]+)/gm)) {
      // Do not copy arbitrary tool/page text into evidence or subsequent model input.
      const type=['boolean-based blind','error-based','UNION query'].find(t=>t.toLowerCase()===m[1].trim().toLowerCase());
      if(type && !techniques.some(t=>t.type===type))techniques.push({type,title:type});
    }
  }
  const ended=/\[\*\] ending @/i.test(text);
  const negativeLine=/^(?:\[[0-9:]+\]\s*)?(?:\[(?:CRITICAL|ERROR)\]\s*)?all tested parameters do not appear to be injectable(?:\..*)?$/i;
  const hasNegative=text.split(/\r?\n/).some(line=>negativeLine.test(line.trim()));
  const remaining=text.split(/\r?\n/).filter(line=>!negativeLine.test(line.trim())).join('\n')+'\n'+(result.stderr||'');
  const failed= result.timedOut || result.aborted || result.outputLimitExceeded || result.processStopped!==true || result.exitCode!==0;
  const interference=/redirect|refresh intent|resuming|cached|not authorized|unauthorized|access denied|\[(?:CRITICAL|ERROR)\]/i.test(remaining);
  const positive=techniques.length>0 && result.success && ended && !failed && !interference && !/\[CRITICAL\]/.test(text);
  const negative=hasNegative && techniques.length===0 && ended && !failed && !interference && !/unable to connect|connection (?:refused|timed out)|no web server found/i.test(remaining);
  return {status:positive?'tool_positive':negative?'not_detected':'inconclusive',techniques,
    complete:!!(positive||negative),report_complete:ended,
    reason:positive?'sqlmap 完整报告检出所选参数':negative?'本次 BEU 策略未检出，不代表不存在其他漏洞':'检测未完成或证据不足，需复核'};
}
export async function detectWebSql({url,parameter,cookie,authorization,request={},signal,timeout=120000,runner=runTool}) {
  const dir=await mkdtemp(join(tmpdir(),'redteam-sqli-'));await chmod(dir,0o700);
  let result;
  try {
    result=await runner('sqlmap',sqlDetectionArgs(url,parameter,cookie,authorization,request),{signal,timeout,privateOutputDir:dir,maxOutputKB:512});
    result.processStopped=result.processStopped===true || result.toolStarted===false;
    if(!result.processStopped)result.privateRunRef=basename(dir);
    return {result,assessment:sqlDetectionResult(result,parameter,request)};
  } catch {
    // A thrown adapter gives no proof that the process stopped. Preserve the lock and directory.
    result={success:false,exitCode:-1,processStopped:false,privateRunRef:basename(dir)};
    return {result,assessment:sqlDetectionResult(result,parameter,request)};
  } finally {
    // Only this generated directory; keep it isolated if process stop is unknown.
    if(result?.processStopped===true)await rm(dir,{recursive:true,force:true}).catch(()=>{if(result)result.privateCleanupFailed=true;});
  }
}
