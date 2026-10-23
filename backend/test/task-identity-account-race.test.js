import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import express from 'express';
import Database from 'better-sqlite3';
import { runMigrations } from '../src/db/migrate.js';
import { authenticate } from '../src/middleware/auth.js';
import { generateAccessToken } from '../src/middleware/jwtUtils.js';
import errorHandler from '../src/middleware/errorHandler.js';
import * as connections from '../src/services/sourceScanConnections.js';

let resolveConnection;
await mock.module('../src/services/sourceScanConnections.js', {
  namedExports: { ...connections, resolveSourceConnection: (...args) => resolveConnection(...args) },
});
const { default: pipelines } = await import('../src/routes/pipelines.js');

test('account changes during async creation reject the save without issuing a number', async t => {
  for (const change of ['disabled', 'deleted', 'role_changed']) {
    await t.test(change, async () => {
      const db = new Database(':memory:');
      db.pragma('foreign_keys=ON');
      await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
      db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','fixture','user')").run();
      let entered, resume;
      const pending = new Promise(resolve => { entered = resolve; });
      const gate = new Promise(resolve => { resume = resolve; });
      resolveConnection = async () => {
        entered();
        await gate;
        return { id: 'fixture-source', kind: 'local' };
      };
      const app = express();
      app.use(express.json());
      app.use('/pipelines', authenticate, pipelines(db));
      app.use(errorHandler);
      const server = await new Promise(resolve => {
        const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
      });
      const body = { target: 'http://192.0.2.10/', request_id: 'async-account-race', config: {
        input_kind: 'remote_directory', source_connection_id: 'fixture-source',
        authorization_confirmed: true, authorization_scope: 'http://192.0.2.10/',
      } };
      const create = async () => {
        const response = await fetch(`http://127.0.0.1:${server.address().port}/pipelines`, {
          method: 'POST', headers: { 'content-type': 'application/json',
            authorization: 'Bearer ' + generateAccessToken({ username: 'owner', role: 'user' }) },
          body: JSON.stringify(body),
        });
        return { http: response.status, ...await response.json() };
      };
      try {
        const request = create();
        await pending;
        if (change === 'disabled') db.prepare("UPDATE users SET is_active=0 WHERE username='owner'").run();
        if (change === 'deleted') db.prepare("DELETE FROM users WHERE username='owner'").run();
        if (change === 'role_changed') db.prepare("UPDATE users SET role='admin' WHERE username='owner'").run();
        resume();
        const rejected = await request;
        assert.equal(rejected.http, 401);
        assert.equal(rejected.error.code, 'AUTH_REQUIRED');
        for (const table of ['pipelines', 'task_number_counters', 'task_creation_requests', 'pipeline_steps', 'scan_tasks'])
          assert.equal(db.prepare(`SELECT count(*) n FROM ${table}`).get().n, 0, table);
        db.prepare("INSERT OR REPLACE INTO users(username,password,role,is_active) VALUES ('owner','fixture','user',1)").run();
        const accepted = await create();
        assert.equal(accepted.http, 201);
        assert.match(accepted.data.task_no, /^TASK-\d{8}-000001$/);
        assert.equal(accepted.data.status, 'created');
        assert.equal(db.prepare('SELECT count(*) n FROM task_creation_requests').get().n, 1);
      } finally {
        resume();
        await new Promise(resolve => server.close(resolve));
        db.close();
      }
    });
  }
});
