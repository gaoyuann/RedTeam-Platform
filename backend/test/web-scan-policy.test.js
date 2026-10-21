import test from 'node:test';
import assert from 'node:assert/strict';
import { webDirectoryScanBlockReason, webPageEntries, directoryOptionsBlockReason } from '../src/services/webScanPolicy.js';

test('directory scanning accepts explicit directory bases and rejects pages, parameters and script PATH_INFO', () => {
  for (const path of ['/', '/app/', '/app.v2/', '/%E5%BA%94%E7%94%A8/'])
    assert.equal(webDirectoryScanBlockReason('http://fixture.invalid' + path), null, path);
  for (const path of ['/login.php', '/login.php/', '/login.php/admin/', '/LOGIN.PHP8/',
    '/login%2ephp/', '/login.php%2fadmin/', '/login%252ephp/', '/app%2f/',
    '/login', '/api/users', '/app/?id=1', '/app/#page', '/index.aspx/', '/index.jsp/',
    '/index.php;session=fixture/', '/%invalid/'])
    assert.equal(typeof webDirectoryScanBlockReason('http://fixture.invalid' + path), 'string', path);
  assert.equal(typeof webDirectoryScanBlockReason('ftp://fixture.invalid/'), 'string');
  assert.equal(typeof webDirectoryScanBlockReason('not a URL'), 'string');
});

test('form identity covers omitted, empty, unquoted and encoded attributes without reading field values',()=>{
  const page='http://fixture.invalid/login/';
  const entries=webPageEntries('<form method=post><input name=token value=secret></form><form action=""></form><form action=/submit/></form><a href="/app/?a=1&amp;b=2">app</a>',page);
  assert.equal(entries.filter(x=>x.kind==='form' && x.value===page).length,2);
  assert.ok(entries.some(x=>x.value==='/submit/'));
  assert.ok(entries.some(x=>x.value==='/app/?a=1&b=2'));
  assert.doesNotMatch(JSON.stringify(entries),/secret/);
  assert.equal(webPageEntries('<!-- <form> --><script>"<form>"</script>',page).length,0);
  assert.ok(webDirectoryScanBlockReason(page,{endpoint:true}));
});

test('directory options cannot change checked target, port, auth, or calibration',()=>{
  for(const tool of ['nikto','ffuf']) for(const extra_args of ['-h http://other.invalid/','-root /login.php','-u http://other.invalid/FUZZ','-r','-no404','-config fixture','-H Cookie:secret', ['-root','/login.php']])
    assert.ok(directoryOptionsBlockReason(tool,'http://fixture.invalid/',{extra_args}),String(extra_args));
  assert.equal(directoryOptionsBlockReason('ffuf','http://fixture.invalid:8080/',{ports:8080,extra_args:'-rate 10 -t 2'}),null);
  assert.ok(directoryOptionsBlockReason('nikto','http://fixture.invalid/',{ports:8080}));
  assert.ok(directoryOptionsBlockReason('nikto','http://fixture.invalid/',{cookie:'session=fixture'}));
  assert.equal(directoryOptionsBlockReason('ffuf','http://fixture.invalid/',{cookie:'session=fixture'}),null);
  assert.ok(directoryOptionsBlockReason('ffuf','http://fixture.invalid/',{cookie:'session=fixture\r\nHost: other'}));
});
