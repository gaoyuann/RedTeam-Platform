import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {loadCscanEnvironment} from '../src/services/cscanEnvironment.js';

test('connection file loads quoted values, preserves overrides, and never evaluates shell input', t=>{
  const dir=mkdtempSync(join(tmpdir(),'cscan-env-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const file=join(dir,'connection.env');
  writeFileSync(file,'# connection\nexport CSCAN_API_URL="http://127.0.0.1:18080"\nCSCAN_TOKEN_FILE=\'/tmp/token file\'\nCSCAN_PROVIDER=$(not-a-command)\n');
  const env={REDTEAM_CSCAN_ENV_FILE:file,CSCAN_API_URL:'http://override.invalid'};
  assert.equal(loadCscanEnvironment(env),true);
  assert.equal(env.CSCAN_API_URL,'http://override.invalid');
  assert.equal(env.CSCAN_TOKEN_FILE,'/tmp/token file');
  assert.equal(env.CSCAN_PROVIDER,'$(not-a-command)');
  writeFileSync(file,'CSCAN_PROVIDER=custom\nOTHER_SECRET=do-not-print\n');
  const invalid={REDTEAM_CSCAN_ENV_FILE:file};
  assert.throws(()=>loadCscanEnvironment(invalid),/仅支持 CSCAN_/);
  assert.equal(invalid.CSCAN_PROVIDER,undefined,'invalid files cannot partially change the environment');
  assert.equal(loadCscanEnvironment({}),false);
  assert.throws(()=>loadCscanEnvironment({REDTEAM_CSCAN_ENV_FILE:join(dir,'missing')}),/无法读取/);
});
