// AK-REV1-AC03 (issue 8): every destination is checked before the first write, and when a later step fails every file
// the run wrote goes, allowed_signers gets its old bytes back, and a second run after the obstacle is removed succeeds
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setup } from '../src/setup.mjs';

const prep = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-rollback-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const key = path.join(d, 'id_human');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'ana@example.com', '-f', key]);
  return { d, h: path.join(d, 'home'), trust: path.join(d, 'trust'), key };
};
const tree = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir, { recursive: true }).sort() : []);

test('allowed_signers as a directory is refused before anything is written, and the run after its removal succeeds', (t) => {
  const { h, trust, key } = prep(t);
  fs.mkdirSync(path.join(trust, 'allowed_signers'), { recursive: true });
  assert.throws(() => setup('ci', { principal: 'ana@example.com', sshKey: key, trust, home: h }), (e) => e.code === 'AGENTKEY_CONFLICT' && /allowed_signers is there and is not a regular file/.test(e.message));
  assert.deepEqual(tree(trust), ['allowed_signers']);
  assert.equal(fs.existsSync(path.join(h, 'keys', 'ci.key')), false);
  fs.rmdirSync(path.join(trust, 'allowed_signers'));
  const r = setup('ci', { principal: 'ana@example.com', sshKey: key, trust, home: h });
  assert.match(r.kid, /^k[0-9a-f]{16}$/);
});

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));

test('a failure at the final check, after every write, removes every file the run wrote and restores allowed_signers', (t) => {
  const { d, h, trust, key } = prep(t);
  // an ssh-keygen on PATH that refuses only -Y verify: everything is written, then the receiver's check fails
  const real = execFileSync('sh', ['-c', 'command -v ssh-keygen'], { encoding: 'utf8' }).trim();
  const shim = path.join(d, 'shim');
  fs.mkdirSync(shim);
  fs.writeFileSync(path.join(shim, 'ssh-keygen'), `#!/bin/sh\nprev=\nfor a; do [ "$prev" = -Y ] && [ "$a" = verify ] && exit 1; prev=$a; done\nexec ${real} "$@"\n`, { mode: 0o755 });
  fs.mkdirSync(trust);
  fs.writeFileSync(path.join(trust, 'allowed_signers'), 'bo@example.com namespaces="agentkey" ssh-ed25519 AAAA\n');
  const before = fs.readFileSync(path.join(trust, 'allowed_signers'));
  const run = (env) => spawnSync(process.execPath, [BIN, 'setup', 'claude-code/reviewer', '--principal', 'ana@example.com', '--ssh-key', key, '--trust', trust],
    { env: { ...process.env, AGENTKEY_HOME: h, ...env }, encoding: 'utf8', timeout: 20_000 });
  const r = run({ PATH: `${shim}:${process.env.PATH}` });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stderr, /does not verify/);
  assert.deepEqual(tree(trust), ['allowed_signers'], 'the three copied files and the directory made for the role are gone');
  assert.deepEqual(fs.readFileSync(path.join(trust, 'allowed_signers')), before, 'allowed_signers has its old bytes');
  for (const f of ['reviewer.key', 'reviewer.pub', 'reviewer.pub.sshsig', 'reviewer.pub.principal']) {
    assert.equal(fs.existsSync(path.join(h, 'keys', 'claude-code', f)), false, f);
  }
  // with the real ssh-keygen, the same command succeeds
  assert.equal(run({}).status, 0);
});

test('a failure at the binding (the SSH public key is not the private key\'s) removes the key it made', (t) => {
  const { d, h, trust, key } = prep(t);
  // the .pub beside the key is another key's: preflight cannot see it, the binding is made, and the final check fails
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'x', '-f', path.join(d, 'other')]);
  fs.copyFileSync(path.join(d, 'other.pub'), `${key}.pub`);
  fs.mkdirSync(trust);
  fs.writeFileSync(path.join(trust, 'allowed_signers'), 'bo@example.com namespaces="agentkey" ssh-ed25519 AAAA\n');
  const before = fs.readFileSync(path.join(trust, 'allowed_signers'));
  assert.throws(() => setup('claude-code/reviewer', { principal: 'ana@example.com', sshKey: key, trust, home: h }), (e) => e.code === 'AGENTKEY_SSH' && /-Y sign failed/.test(e.message));
  assert.deepEqual(tree(trust), ['allowed_signers'], 'nothing was copied');
  assert.deepEqual(fs.readFileSync(path.join(trust, 'allowed_signers')), before);
  for (const f of ['reviewer.key', 'reviewer.pub', 'reviewer.pub.sshsig', 'reviewer.pub.principal']) {
    assert.equal(fs.existsSync(path.join(h, 'keys', 'claude-code', f)), false, f);
  }
  // with the right .pub back, the same command succeeds
  fs.writeFileSync(`${key}.pub`, execFileSync('ssh-keygen', ['-y', '-f', key], { encoding: 'utf8' }));
  assert.match(setup('claude-code/reviewer', { principal: 'ana@example.com', sshKey: key, trust, home: h }).kid, /^k[0-9a-f]{16}$/);
});
