import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import { rbacGuard } from '../src/middleware/rbac.js';

let reply, calls;
await mock.module('../src/services/llmClient.js', { namedExports: { callLlm: async (messages, options) => {
  calls.push({ messages, options });
  if (reply instanceof Error) throw reply;
  return reply;
} } });
const { default: configRoutes } = await import('../src/routes/config.js');

test('connection test calls the model, enforces admin access, preserves data and sanitizes errors', async t => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE system_config(config_key TEXT PRIMARY KEY, config_value TEXT, category TEXT, description TEXT, updated_at TEXT)');
  db.prepare("INSERT INTO system_config(config_key,config_value,category) VALUES ('default',?,'llm')")
    .run(JSON.stringify({key:'fixture-secret',url:'https://fixture.invalid/v1',model:'fixture'}));
  const before = db.prepare('SELECT * FROM system_config').all();
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = {role:req.headers['x-role']}; next(); });
  app.use('/api/config', rbacGuard('config'), configRoutes(db));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const request = role => fetch(`http://127.0.0.1:${server.address().port}/api/config/llm/test-connection`, {
    method:'POST', headers:{'x-role':role,'content-type':'application/json'}, body:'{}',
  });
  calls = []; reply = {ok:true,content:'OK'};
  assert.equal((await request('user')).status, 403);
  assert.equal(calls.length, 0);
  const good = await request('admin');
  assert.equal(good.status, 200);
  assert.match((await good.json()).data.message, /测试通过/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.timeoutMs, 20000);
  assert.equal(calls[0].options.maxTokens, 256);
  assert.doesNotMatch(JSON.stringify(calls[0]), /fixture-secret|scan|target/);
  for (const result of [
    {ok:true,content:'',hasReasoning:true,finishReason:'length'},
    {ok:true,content:'',hasReasoning:true,finishReason:'stop'},
    {ok:true,content:'O',hasReasoning:false,finishReason:'length'},
  ]) {
    reply = result;
    const response = await request('admin');
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.truncated, result.finishReason === 'length');
    assert.match(body.data.message, /模型连接成功/);
    assert.match(body.data.message, result.finishReason === 'length' ? /长度上限/ : /未返回最终回答/);
    assert.doesNotMatch(JSON.stringify(body), /reasoning_content|fixture-secret/);
  }
  for (const [result, code, status] of [
    [{ok:false,error:'LLM API 401: fixture-secret'},'LLM_AUTH_ERROR',400],
    [{ok:false,error:'LLM API 429: fixture-secret'},'LLM_QUOTA_ERROR',400],
    [{ok:false,error:'LLM request timed out'},'LLM_TIMEOUT',400],
    [{ok:false,error:'LLM request failed: fixture-secret'},'LLM_NETWORK_ERROR',400],
    [{ok:false,error:'No LLM API key configured'},'LLM_NOT_CONFIGURED',400],
    [{ok:true,content:'  '},'LLM_EMPTY_RESPONSE',400],
    [{ok:true,content:'',hasReasoning:false,finishReason:'length'},'LLM_EMPTY_RESPONSE',400],
    [new Error('fixture-secret'),'LLM_SERVICE_ERROR',500],
  ]) {
    reply = result;
    const response = await request('admin');
    assert.equal(response.status, status);
    const body = await response.json();
    assert.equal(body.error.code, code);
    assert.doesNotMatch(JSON.stringify(body), /fixture-secret/);
  }
  assert.deepEqual(db.prepare('SELECT * FROM system_config').all(), before);
});
