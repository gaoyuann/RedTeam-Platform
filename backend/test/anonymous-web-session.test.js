import test from 'node:test';
import assert from 'node:assert/strict';
import {createAnonymousWebSession} from '../src/services/anonymousWebSession.js';
import {parseResults} from '../src/services/scanResultParsers.js';
test('generic HTML needs no DVWA marker and never forwards response cookies',async()=>{
 let calls=0;const session=createAnonymousWebSession({target:'http://fixture.test/',allowUrl:u=>u.startsWith('http://fixture.test/'),request:async(_url,options)=>{
  calls++;assert.equal(options.headers,undefined);return new Response('<form><input name="id" value="1"></form>',{headers:{'set-cookie':'private=do-not-forward'}});
 }});
 assert.equal((await session.login()).status,200);assert.equal((await session.read('http://fixture.test/page')).status,200);assert.equal(session.cookieFor('http://fixture.test/'),'');assert.equal(calls,2);session.close();
 await assert.rejects(session.read('http://fixture.test/'));
});
test('redirects cannot leave explicit origin even when scope predicate is permissive',async()=>{
 let calls=0;const s=createAnonymousWebSession({target:'http://fixture.test/',allowUrl:()=>true,request:async()=>{calls++;return new Response('',{status:302,headers:{location:'http://outside.test/'}});}});
 await assert.rejects(s.login(),/超出允许范围/);assert.equal(calls,1);s.close();
});
test('Nikto separators and information records do not become medium vulnerability findings',()=>{
 const rows=parseResults('web_scan_nikto','+ OSVDB-3268: /config/: Directory indexing found.\n+ /login.php: Admin login page/section found.\n+ OSVDB-3233: /icons/README: Apache default file found.');
 assert.equal(rows[0].result_data.path,'/config/');assert.equal(rows[0].result_type,'web_vuln');
 assert.equal(rows[1].result_type,'information');assert.equal(rows[2].result_type,'information');assert.equal(rows[2].result_data.path,'/icons/README');
});
