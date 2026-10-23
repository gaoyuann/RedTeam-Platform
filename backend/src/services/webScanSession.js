import {attributes, allowedPage, privateField} from './webScanEntries.js';

const loginForm = html => [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)].find(m=>/type\s*=\s*["']?password/i.test(m[2]));
const authenticated = html => /logout\.php/i.test(html) && !loginForm(html);
// Cookies and raw pages are deliberately confined to this runtime object.
export function createWebScanSession({target,credentials,allowUrl,signal,request=fetch,maxPages=20,onObservation=()=>{}}) {
  const origin=new URL(target).origin, jar=new Map();let pages=0, refreshes=0, closed=false, securityLevel=null;
  const secrets=new Set();
  function remember(value){if(value)for(const s of [value,encodeURIComponent(value),new URLSearchParams({v:value}).toString().slice(2)])secrets.add(s);}
  remember(credentials.username);remember(credentials.password);
  function validate(url) {
    const u=new URL(url);
    if(closed || u.origin!==origin || !allowedPage(u.href,target,allowUrl) || [...u.searchParams.keys()].some(privateField) ||
      /(?:security|setup|logout|reset|install)\.php/i.test(u.pathname))throw new Error('认证或页面请求超出允许范围');
    return u;
  }
  function cookieFor(url) {
    const path=new URL(url).pathname;
    return [...jar.values()].filter(c=>(!c.secure||url.startsWith('https:')) && (path===c.path || path.startsWith(c.path.endsWith('/')?c.path:c.path+'/')))
      .map(c=>`${c.name}=${c.value}`).join('; ');
  }
  async function send(input, options={}) {
    let u=validate(input);
    for(let redirects=0;redirects<=5;redirects++) {
      signal?.throwIfAborted();if(pages>=maxPages)throw new Error('页面请求预算已用尽');pages++;
      const controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});
      const timer=setTimeout(abort,10000);let response,text='';
      try {
        response=await request(u.href,{...options,signal:controller.signal,redirect:'manual',headers:{...options.headers,Cookie:cookieFor(u.href)}});
        const headers=(response.headers.getSetCookie?.() || [response.headers.get('set-cookie')||''])
          .flatMap(header=>header.split(/,(?=\s*[^;,=]+=[^;])/));
        for(const header of headers) {
          const parts=header.split(';').map(s=>s.trim()), pair=parts.shift(),i=pair.indexOf('=');if(i<=0)continue;
          const name=pair.slice(0,i),value=pair.slice(i+1);
          if(!/^[\w-]{1,80}$/.test(name)||/[\r\n]/.test(value))continue;
          let path=u.pathname.slice(0,u.pathname.lastIndexOf('/')+1)||'/';
          const explicit=parts.find(p=>/^path=/i.test(p));if(explicit?.slice(5).startsWith('/'))path=explicit.slice(5);
          const domain=parts.find(p=>/^domain=/i.test(p));if(domain && domain.slice(7).replace(/^\./,'')!==u.hostname)continue;
          if(jar.size>=20 && !jar.has(name+path))throw new Error('会话 Cookie 超过限制');
          if(name==='security') {
            if(!['low','medium','high','impossible'].includes(value) || securityLevel && value!==securityLevel)
              throw new Error('DVWA 会话安全等级发生变化或无效');
            securityLevel=value;
          } else remember(value);
          jar.set(name+path,{name,value,path,secure:parts.some(p=>/^secure$/i.test(p))});
        }
        if(response.body) {
          const reader=response.body.getReader();let bytes=0;const decoder=new TextDecoder();
          try {while(true){const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.length;if(bytes>262144)throw new Error('页面响应超过限制');text+=decoder.decode(chunk.value,{stream:true});}text+=decoder.decode();}
          finally {await reader.cancel().catch(()=>{});}
        }
      } catch(e) {if(signal?.aborted)throw new Error('扫描已取消');if(['页面响应超过限制','DVWA 会话安全等级发生变化或无效'].includes(e.message))throw e;throw new Error('页面请求失败或超时');}
      finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}
      if(response.status>=300&&response.status<400&&response.headers.get('location')) {
        if(options.method==='POST' && ![301,302,303].includes(response.status))throw new Error('拒绝将临时登录信息重放到跳转地址');
        u=validate(new URL(response.headers.get('location'),u).href);
        if([301,302,303].includes(response.status))options={};
        continue;
      }
      const observed=new URL(u);observed.search='';observed.hash='';
      onObservation({url:observed.href,status_code:response.status,authenticated:authenticated(text)});
      if(!response.ok)throw new Error('页面未返回成功响应');
      return {url:u.href,text,status:response.status};
    }
    throw new Error('页面跳转次数超过限制');
  }
  async function login() {
    let page=await send(target);
    if(authenticated(page.text)){checkSecurity(page.url);return page;}
    let form=loginForm(page.text);
    if(!form) {
      const link=[...page.text.matchAll(/<a\b[^>]*>/gi)].map(m=>attributes(m[0]).href).filter(Boolean)
        .map(h=>allowedPage(h,page.url,allowUrl)).find(u=>u && /\/login\.php$/i.test(u.pathname));
      if(!link)throw new Error('未观察到 DVWA 登录入口');
      page=await send(link.href);form=loginForm(page.text);
    }
    if(!form || !/DVWA|Damn Vulnerable Web Application/i.test(page.text))throw new Error('未确认 DVWA 登录表单');
    const a=attributes(form[1]);if((a.method||'GET').toUpperCase()!=='POST')throw new Error('不支持的登录表单');
    const body=new URLSearchParams();let token=false;
    for(const m of form[2].matchAll(/<input\b[^>]*>/gi)) {
      const f=attributes(m[0]);if(!f.name)continue;
      if(f.name==='user_token'&&f.value){body.set(f.name,f.value);remember(f.value);token=true;}
      if(f.name==='Login')body.set('Login',f.value||'Login');
    }
    if(!token)throw new Error('DVWA 登录令牌缺失');
    body.set('username',credentials.username);body.set('password',credentials.password);body.set('Login',body.get('Login')||'Login');
    page=await send(new URL(a.action||page.url,page.url).href,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()});
    if(!authenticated(page.text))throw new Error('登录未成功，未开展认证检测');
    checkSecurity(page.url);
    return page;
  }
  function checkSecurity(url) {
    const values=cookieFor(url).split('; ').filter(c=>c.startsWith('security=')).map(c=>c.slice(9));
    if(!securityLevel || values.length!==1 || values[0]!==securityLevel)throw new Error('未确认本次 DVWA 会话的安全等级 Cookie，未开展检测');
    return securityLevel;
  }
  return {
    login,
    async read(url) {
      let page=await send(url);
      if(loginForm(page.text) || /\/login\.php$/i.test(new URL(page.url).pathname)) {
        if(refreshes++)throw new Error('认证会话再次失效');
        await login();page=await send(url);
        if(loginForm(page.text))throw new Error('认证会话未恢复');
      }
      if(!authenticated(page.text))throw new Error('未确认页面仍处于 DVWA 登录状态');
      checkSecurity(url);
      return page;
    },
    cookieFor,
    securityLevelFor:checkSecurity,
    scrub(value) {let text=String(value);for(const s of secrets)if(s)text=text.split(s).join('[已隐藏]');return text;},
    get pages(){return pages;},
    close(){closed=true;jar.clear();secrets.clear();credentials.password='';credentials.username='';},
  };
}
