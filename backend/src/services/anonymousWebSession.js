import {sessionAllows,scrubSession} from './scanSessionAuth.js';
// Unauthenticated HTTP observation. Never guesses credentials or follows off-scope redirects.
import {allowedPage} from './webScanEntries.js';
export function createAnonymousWebSession({target,allowUrl,signal,authentication,request=fetch,maxPages=20,onObservation=()=>{}}){
 let pages=0,closed=false;const origin=new URL(target).origin;
 async function read(input,post){
  let url=new URL(input);
  for(let i=0;i<6;i++){
   signal?.throwIfAborted();if(closed||pages>=maxPages)throw Error('页面请求预算已用尽');
   if((authentication&&!sessionAllows(authentication,url))||url.origin!==origin||!allowedPage(url.href,target,allowUrl))throw Error('认证或页面请求超出允许范围');
   pages++;const ctrl=new AbortController(),abort=()=>ctrl.abort();signal?.addEventListener('abort',abort,{once:true});const timer=setTimeout(abort,10000);
   try{
    const r=await request(url.href,{method:post?'POST':'GET',...(post?{body:post.body,headers:{'Content-Type':post.contentType}}:{}),redirect:'manual',signal:ctrl.signal,...(authentication?{headers:{...(post?{'Content-Type':post.contentType}:{}),...(authentication.type==='cookie'?{Cookie:authentication.value}:{Authorization:'Bearer '+authentication.value})}}:{})});
    if(r.status>=300&&r.status<400&&r.headers.get('location')){await r.body?.cancel();if(post)throw Error('POST 跳转被拒绝，未重放请求');url=new URL(r.headers.get('location'),url);continue;}
    if(authentication&&(r.status===401||r.status===403)){await r.body?.cancel();throw Error('临时会话失效或无权访问，未开展认证检测');}
    if(!r.ok){await r.body?.cancel();throw Error('页面未返回成功响应');}
    const reader=r.body?.getReader();let text='',bytes=0;const decoder=new TextDecoder();
    if(reader)try{while(true){const v=await reader.read();if(v.done)break;bytes+=v.value.length;if(bytes>262144)throw Error('页面响应超过限制');text+=decoder.decode(v.value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel().catch(()=>{});}
    if(authentication&&/<input\b[^>]*type\s*=\s*["']?password/i.test(text))throw Error('临时会话未通过登录页，未开展认证检测');
    const publicUrl=new URL(url);publicUrl.search='';publicUrl.hash='';onObservation({url:publicUrl.href,status_code:r.status,authenticated:false});
    return {url:url.href,text,status:r.status};
   }finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }throw Error('页面跳转次数超过限制');
 }
 return {login:()=>read(target),read,readEntry:e=>read(e.requestUrl,e.method==='POST'?e:undefined),cookieFor:url=>authentication?.type==='cookie'&&sessionAllows(authentication,url)?authentication.value:'',securityLevelFor:()=>null,scrub:value=>scrubSession(authentication,String(value)),authorizationFor:url=>authentication?.type==='bearer'&&sessionAllows(authentication,url)?'Bearer '+authentication.value:'',get pages(){return pages;},close(){closed=true;if(authentication)authentication.value='';}};
}
