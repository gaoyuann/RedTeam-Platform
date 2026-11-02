import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import * as childProcess from 'node:child_process';
import express from 'express';
import http from 'node:http';
import { promisify } from 'node:util';

let engine = 'docker';
let failImages = false;
let calls = 0;
function execFixture() { throw new Error('Use the async fixture'); }
execFixture[promisify.custom] = async (command, options) => {
  ++calls;
  assert.ok(options.timeout <= 5000);
  if (command.includes(' images ')) {
    if (failImages) throw new Error('fixture failure');
    return { stdout: 'rt-recon:latest\t737MB\nrt-web:latest\t117MB\n<none>:<none>\t1MB\n', stderr: '' };
  }
  return { stdout: '27.0.0\n', stderr: '' };
};
await mock.module('../src/tools/containerEngine.js', { namedExports: { getEngine: async () => engine } });
await mock.module('child_process', { namedExports: {
  ...childProcess,
  exec: execFixture,
} });
const { default: toolRoutes } = await import('../src/routes/tools.js');

test('tool inventory preserves existing fields and distinguishes built-in, virtual and container handlers', async t => {
  const app = express(); app.use('/tools', toolRoutes(null));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const request = async path => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/tools${path}`);
    assert.equal(response.status, 200);
    return response.json();
  };
  const list = await request('/list');
  assert.equal(calls, 0, 'listing tools does not probe or execute tools');
  assert.equal(list.meta.total, list.data.length);
  assert.equal(new Set(list.data.map(row => row.toolId)).size, list.data.length);
  for (const row of list.data) {
    assert.equal(typeof row.virtual, 'boolean');
    assert.ok(row.image === null || typeof row.image === 'string');
    assert.ok(row.purpose && row.purpose !== '已注册工具', row.toolId);
  }
  assert.equal(list.data.find(row => row.toolId === 'nmap').executionMode, 'container');
  assert.equal(list.data.find(row => row.toolId === 'target-request').executionMode, 'builtin');
  assert.equal(list.data.find(row => row.toolId === 'source-code-runner').executionMode, 'builtin');
  assert.equal(list.data.find(row => row.toolId === 'webshell').executionMode, 'virtual');

  const loaded = (await request('/containers/status')).data;
  assert.equal(loaded.imageInventoryStatus, 'ok');
  assert.deepEqual(loaded.images, ['rt-recon:latest', 'rt-web:latest']);
  assert.equal(loaded.imageSizes['rt-web:latest'], '117MB');
  assert.equal(loaded.imageCapabilities['rt-cloud'], '云环境测试');
  assert.equal(loaded.imageCapabilities['rt-capture'], '网络抓包与分析');
  for (const reference of loaded.expectedImages) {
    assert.equal(typeof loaded.imageCapabilities[reference.slice(0, -':latest'.length)], 'string');
  }
  assert.ok(!loaded.expectedImages.includes('builtin:latest'));
  assert.equal(loaded.loadedCount, 2);
  assert.equal(loaded.expectedCount, loaded.expectedImages.length);
  assert.equal(loaded.allLoaded, false);

  failImages = true;
  const failed = (await request('/containers/status')).data;
  assert.equal(failed.imageInventoryStatus, 'error');
  assert.equal(failed.allLoaded, false);
  assert.deepEqual(failed.images, []);
  failImages = false;
  assert.equal((await request('/containers/status')).data.imageInventoryStatus, 'ok');
  engine = 'host';
  const before = calls;
  assert.equal((await request('/containers/status')).data.imageInventoryStatus, 'unavailable');
  assert.equal(calls, before, 'host mode does not launch a container engine command');
});
