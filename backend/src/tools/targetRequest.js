import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { sourceTarget } from '../services/sourceScanConnections.js';

// A bounded request against one explicit deployment endpoint, with no redirects.
export function parseTargetRequest(args, authorizedTarget) {
  if (!Array.isArray(args) || args.length !== 1) throw new Error('target-request 接受一个 JSON 请求参数');
  const spec = JSON.parse(args[0]);
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new Error('请求格式无效');
  const url = new URL(sourceTarget(spec.url));
  if (authorizedTarget) {
    const authorized = new URL(sourceTarget(authorizedTarget));
    if (url.protocol !== authorized.protocol || url.host !== authorized.host) throw new Error('请求超出任务的协议、主机或端口范围');
  }
  const timeout = spec.timeout_ms ?? 10000;
  if (!Number.isInteger(timeout) || timeout < 500 || timeout > 30000) throw new Error('请求超时须为 500–30000 毫秒');
  if (url.protocol === 'tcp:') {
    const exchanges = spec.exchanges ?? [];
    if (!Array.isArray(exchanges) || exchanges.length > 10) throw new Error('TCP 交互最多 10 轮');
    let bytes = 0;
    for (const exchange of exchanges) {
      if (!exchange || typeof exchange.send !== 'string' || !Number.isInteger(exchange.wait_ms ?? 300) || (exchange.wait_ms ?? 300) < 0 || (exchange.wait_ms ?? 300) > 2000) throw new Error('TCP 交互须包含 send 文本和 0–2000 毫秒 wait_ms');
      if (exchange.expect !== undefined && (typeof exchange.expect !== 'string' || !exchange.expect || Buffer.byteLength(exchange.expect)>1024)) throw new Error('TCP expect 须为 1–1024 字节的提示文本');
      if (!Number.isInteger(exchange.expect_timeout_ms ?? 3000) || (exchange.expect_timeout_ms ?? 3000)<100 || (exchange.expect_timeout_ms ?? 3000)>10000) throw new Error('TCP 提示等待须为 100–10000 毫秒');
      bytes += Buffer.byteLength(exchange.send);
    }
    if (bytes > 8192) throw new Error('TCP 输入超过 8 KB');
    return { url, timeout, exchanges };
  }
  const method = spec.method || 'GET';
  if (!['GET','HEAD','POST','OPTIONS'].includes(method)) throw new Error('HTTP 方法不支持');
  const body = spec.body ?? '';
  if (typeof body !== 'string' || Buffer.byteLength(body) > 8192) throw new Error('HTTP 请求正文超过 8 KB');
  const headers = spec.headers ?? {};
  if (!headers || typeof headers !== 'object' || Array.isArray(headers) || Object.keys(headers).length > 20) throw new Error('请求头无效');
  for (const [key,value] of Object.entries(headers)) {
    if (!['accept','content-type','cookie','authorization','user-agent'].includes(key.toLowerCase()) || typeof value !== 'string' || /[\r\n]/.test(value) || value.length > 4096) throw new Error('请求头不支持或过长');
  }
  return { url, timeout, method, body, headers };
}
export async function runTargetRequest(args, options = {}) {
  let spec;
  try { spec = parseTargetRequest(args, options.target); }
  catch (error) { return { success:false, exitCode:1, stdout:'', stderr:error.message, error:error.message, executionMode:'builtin' }; }
  const start = Date.now();
  return new Promise(resolve => {
    let socket, request, timer, idle, sequence, promptTimer, done = false, connected = false, bytes = 0, statusCode, responseHeaders;
    const chunks = [], sent = [], transcript = [];
    let transcriptBytes=0;
    const trace=(direction,data)=>{
      // Coalesce adjacent reads: packet fragmentation must not inflate the log.
      const remaining=Math.max(0,73728-transcriptBytes), part=Buffer.from(data).subarray(0,remaining);
      if(!part.length) return;
      transcriptBytes+=part.length;
      const previous=transcript.at(-1), content=part.toString('base64');
      if(previous?.direction===direction) previous.data=Buffer.concat([Buffer.from(previous.data,'base64'),part]).toString('base64');
      else transcript.push({direction,elapsed_ms:Date.now()-start,encoding:'base64',data:content});
    };
    const finish = (error = null, flags = {}) => {
      if (done) return;
      done = true;
      clearTimeout(timer); clearTimeout(idle); clearTimeout(sequence); clearTimeout(promptTimer);
      options.signal?.removeEventListener('abort', abort);
      socket?.destroy(); request?.destroy();
      const observation = { url: spec.url.href, protocol: spec.url.protocol, connected,
        ...(statusCode !== undefined ? { status_code:statusCode, response_headers:responseHeaders } : {}),
        ...(spec.exchanges ? { sent, transcript } : { method:spec.method }),
        response:Buffer.concat(chunks).toString('utf8'), received_bytes:bytes,
        verification_status:'needs_review' };
      resolve({ success:!error, exitCode:error ? 1 : 0, stdout:JSON.stringify(observation),
        stderr:error || '', error, executionMode:'builtin', durationMs:Date.now()-start, ...flags });
    };
    const abort = () => finish('请求已取消', {aborted:true});
    const collect = chunk => {
      const data = Buffer.from(chunk);
      const remaining = Math.max(0, 65536-bytes);
      chunks.push(data.subarray(0,remaining)); bytes += data.length;
      if(spec.exchanges) trace('receive',data.subarray(0,remaining));
      if (bytes > 65536) finish('响应超过 64 KB，已保存部分证据', {outputLimitExceeded:true});
    };
    options.signal?.addEventListener('abort', abort, {once:true});
    if (options.signal?.aborted) return abort();
    timer = setTimeout(()=>finish('目标请求超时', {timedOut:true}), Math.min(spec.timeout, options.timeout || 30000));
    if (spec.url.protocol === 'tcp:') {
      socket = net.connect({host:spec.url.hostname.replace(/^\[|\]$/g,''), port:Number(spec.url.port)});
      const quietFinish = () => { clearTimeout(idle); idle = setTimeout(()=>finish(),1200); };
      let sentAll = false, index = 0, waiting = null, pending = Buffer.alloc(0);
      const advance = () => {
        if(done) return;
        if(index>=spec.exchanges.length) {sentAll=true; quietFinish();return;}
        waiting=spec.exchanges[index];
        if(waiting.expect) promptTimer=setTimeout(()=>finish('未收到预期 TCP 提示，已停止后续输入',{promptTimedOut:true}),waiting.expect_timeout_ms ?? 3000);
        sendWhenReady();
      };
      const sendWhenReady = () => {
        if(done || !waiting) return;
        if(waiting.expect) {
          const token=Buffer.from(waiting.expect), offset=pending.indexOf(token);
          if(offset<0) return;
          pending=pending.subarray(offset+token.length);
        } else pending=Buffer.alloc(0);
        clearTimeout(promptTimer);
        const exchange=waiting;waiting=null;
        sequence=setTimeout(()=>{
          if(done) return;
          sent.push(exchange.send);trace('send',exchange.send);
          socket.write(exchange.send);index++;advance();
        },exchange.wait_ms ?? 300);
      };
      socket.on('connect',()=>{connected=true;advance();});
      socket.on('data',chunk=>{
        collect(chunk);
        if(done) return;
        pending=Buffer.concat([pending,chunk]);
        sendWhenReady();
        if(sentAll) quietFinish();
      });
      socket.on('end', ()=>finish(sent.length < spec.exchanges.length ? '目标提前关闭连接，交互未完成' : null));
      socket.on('error', error=>finish(error.message));
    } else {
      const transport = spec.url.protocol === 'https:' ? https : http;
      request=transport.request(spec.url, {method:spec.method, headers:spec.headers}, response=>{
        connected=true; statusCode=response.statusCode;
        responseHeaders=Object.fromEntries(Object.entries(response.headers).filter(([name])=>['content-type','location','server','www-authenticate'].includes(name)));
        response.on('data',collect);
        response.on('end',()=>finish());
        response.on('error',error=>finish(error.message));
        response.on('aborted',()=>finish('HTTP 响应被截断'));
      });
      request.on('error',error=>finish(error.message));
      request.end(spec.body);
    }
  });
}
