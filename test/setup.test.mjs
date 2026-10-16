// AK-SETUP-AC01: setup in an empty home makes the key, the binding and the four trust files in one run, the receiver
// then checks both an envelope and the binding from the trust directory alone, and a second run writes nothing
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setup, verifyBinding } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-setup-test-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
const sshKey = (dir, principal) => {
  const f = path.join(dir, 'id_human');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', principal, '-f', f]);
  return f;
};
// every file under the given directories with its bytes and mtime, for "a second run changes nothing"
const snapshot = (...dirs) => {
  const out = {};
  const go = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) go(p);
      else out[p] = [fs.readFileSync(p).toString('base64'), fs.statSync(p).mtimeMs];
    }
  };
  for (const d of dirs) go(d);
  return out;
};

test('one run from an empty home: key, binding and trust files, and the receiver checks both from the trust directory', (t) => {
  const d = scratch(t), h = path.join(d, 'home'), trust = path.join(d, 'trust');
  const key = sshKey(d, 'ana@example.com');
  const env = { ...process.env, AGENTKEY_HOME: h };
  const r = setup('claude-code', { principal: 'ana@example.com', sshKey: key, trust, env, home: h });
  assert.equal(r.role, 'claude-code');
  assert.match(r.kid, /^k[0-9a-f]{16}$/);
  assert.equal(r.principal, 'ana@example.com');
  assert.equal(r.trust, path.resolve(trust));
  assert.match(r.sign, /^agentkey sign claude-code --type /);
  for (const f of ['claude-code.pub', 'claude-code.pub.sshsig', 'claude-code.pub.principal', 'allowed_signers']) {
    assert.ok(fs.existsSync(path.join(trust, f)), `${f} in the trust directory`);
  }
  assert.ok(fs.existsSync(path.join(h, 'keys', 'claude-code.key')));

  // the receiver: the binding from the trust directory's copy, and an envelope the role signs, through the command
  assert.deepEqual(verifyBinding(path.join(trust, 'claude-code.pub'), path.join(trust, 'allowed_signers')), { status: 'bound', kid: r.kid, principal: 'ana@example.com' });
  const env2 = { ...env };
  const signed = spawnSync(process.execPath, [BIN, 'sign', 'claude-code', '--type', 'application/json'], { input: '{"task":"T-1"}', env: env2 });
  assert.equal(signed.status, 0, String(signed.stderr));
  const v = spawnSync(process.execPath, [BIN, 'verify', '--keys', trust], { input: signed.stdout, env: env2 });
  assert.equal(v.status, 0, String(v.stderr));
  assert.equal(String(v.stdout).trim(), `verified ${r.kid}`);

  // a second run: same kid, and not one byte or mtime changed under the home or the trust directory
  const before = snapshot(h, trust);
  const again = setup('claude-code', { principal: 'ana@example.com', sshKey: key, trust, env, home: h });
  assert.equal(again.kid, r.kid);
  assert.deepEqual(again.wrote, []);
  assert.deepEqual(snapshot(h, trust), before);
});

test('a second role goes into the same trust directory and the allowed_signers line is not repeated', (t) => {
  const d = scratch(t), h = path.join(d, 'home'), trust = path.join(d, 'trust');
  const key = sshKey(d, 'ana@example.com');
  const env = { ...process.env, AGENTKEY_HOME: h };
  setup('owner', { principal: 'ana@example.com', sshKey: key, trust, env, home: h });
  const r = setup('claude-code/reviewer', { principal: 'ana@example.com', sshKey: key, trust, env, home: h });
  assert.equal(fs.readFileSync(path.join(trust, 'allowed_signers'), 'utf8').trim().split('\n').length, 1);
  assert.equal(verifyBinding(path.join(trust, 'claude-code', 'reviewer.pub'), path.join(trust, 'allowed_signers')).status, 'bound');
  assert.equal(verifyBinding(path.join(trust, 'owner.pub'), path.join(trust, 'allowed_signers')).status, 'bound');
  assert.match(r.kid, /^k[0-9a-f]{16}$/);
});
