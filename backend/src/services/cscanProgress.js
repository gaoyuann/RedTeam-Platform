import {createHash} from 'node:crypto';

export const cscanReportHash = report => createHash('sha256').update(report).digest('hex');

// Parse completed subtask reports in the background while the scanner keeps
// polling. Results are provisional annotations on raw evidence, never findings.
export function createCscanProgressParser({parse,normalize,onReport,signal,timeoutMs=900000,maxReports=64,maxBytes=128*1024}) {
  const entries=new Map();
  let closed=false,active=null,runningEntry=null;
  const current=entry=>!closed && !signal?.aborted && entries.get(entry.key)===entry;
  const decorate=entry=>({...entry.raw,progress_analysis:{...entry.analysis,report_hash:entry.hash}});
  const close=()=>{closed=true;active?.abort();};
  signal?.addEventListener('abort',close,{once:true});
  const publish=async entry=>{
    if(current(entry)) await onReport(decorate(entry));
  };
  const run=async entry=>{
    const controller=new AbortController();active=controller;runningEntry=entry;
    entry.attempts++;
    let timer;
    try {
      // The race also bounds providers that fail to honour AbortSignal.
      const stopped=new Promise((_,reject)=>{
        controller.signal.addEventListener('abort',()=>reject(new Error('阶段报告解析超时或已取消')),{once:true});
        timer=setTimeout(()=>controller.abort(),timeoutMs);
      });
      const parsed=await Promise.race([parse(entry.raw.report,controller.signal),stopped]);
      if(!current(entry)) return;
      const findings=[],errors=[...(parsed.parse_errors || [])];
      if(parsed.source_access_reported!=='unavailable') for(const finding of parsed.findings) {
        try {findings.push(normalize(finding,entry.raw.report));}
        catch {errors.push('阶段发现缺少原文中的有效源码定位或依据');}
      }
      entry.analysis={state:errors.length?'error':'complete',findings,parse_errors:[...new Set(errors)]};
      await publish(entry);
    } catch {
      if(current(entry)) {
        entry.analysis={state:'error',findings:entry.analysis.findings || [],parse_errors:['阶段报告暂未解析，原始报告已保留']};
        try {await publish(entry);} catch { /* Final report persistence remains independent. */ }
      }
    } finally {
      clearTimeout(timer);active=null;runningEntry=null;
      start();
    }
  };
  function start() {
    if(closed || signal?.aborted || active) return;
    const entry=[...entries.values()].find(item=>item.analysis.state==='pending');
    if(entry) void run(entry);
  }
  return {
    observe(raw,{analyze=true}={}) {
      if(closed || signal?.aborted) return raw;
      const key=JSON.stringify([raw.report_source,raw.source_task_ids,raw.source_subtask_ids]);
      const hash=cscanReportHash(raw.report);
      let entry=entries.get(key);
      if(entry?.hash===hash) {
        entry.raw=raw;
        if(analyze && raw.status==='finished' && entry.analysis.state==='error' && entry.attempts<3 && entry!==runningEntry)
          entry.analysis={...entry.analysis,state:'pending'};
        return decorate(entry);
      }
      if(!analyze || raw.status!=='finished' || /^\s*Source-Access:\s*unavailable\s*$/mi.test(raw.report)) return raw;
      if((entries.size>=maxReports && !entry) || Buffer.byteLength(raw.report)>maxBytes) {
        return {...raw,progress_analysis:{state:'error',report_hash:hash,findings:[],parse_errors:['阶段预览达到解析上限，最终仍处理完整报告']}};
      }
      entry={key,hash,raw,attempts:0,analysis:{state:'pending',findings:[],parse_errors:[]}};
      entries.set(key,entry);
      return decorate(entry);
    },
    start,
    close() {close();signal?.removeEventListener('abort',close);},
  };
}
