// AK-SETUP-AC02: setup checks every prerequisite before it writes. A missing piece exits 2 and is named on stderr, and
// no key file exists in the home afterwards; a trust directory or a binding that belongs to another key is refused and
// left as it was
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-setup-refuses-'));
  t.after(() => { try { fs.chmodSync(path.join(d, 'trust'), 0o700); } catch {} fs.rmSync(d, { recursive: true, force: true }); });
  return d;
};
const sshKey = (dir, name, principal) => {
  const f = path.join(dir, name);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', principal, '-f', f]);
  return f;
};
const run = (d, args, env = {}) => spawnSync(process.execPath, [BIN, 'setup', 'claude-code', '--principal', 'ana@example.com', '--trust', path.join(d, 'trust'), ...args], {
  env: { ...process.env, AGENTKEY_HOME: path.join(d, 'home'), ...env }, encoding: 'utf8', timeout: 20_000,
});
const noKey = (d) => assert.equal(fs.existsSync(path.join(d, 'home', 'keys', 'claude-code.key')), false, 'no key file in the home');

test('no SSH key: exit 2, the key named, nothing written', (t) => {
  const d = scratch(t);
  const r = run(d, ['--ssh-key', path.join(d, 'absent')]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /no SSH key at .*absent/);
  noKey(d);
  assert.equal(fs.existsSync(path.join(d, 'trust')), false);
});

test('an SSH key without its .pub: exit 2, the public key named, nothing written', (t) => {
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  fs.rmSync(`${k}.pub`);
  const r = run(d, ['--ssh-key', k]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /no SSH public key at .*id_human\.pub/);
  noKey(d);
});

test('no ssh-keygen on PATH: exit 2, ssh-keygen named, nothing written', (t) => {
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  fs.mkdirSync(path.join(d, 'empty-path'));
  const r = run(d, ['--ssh-key', k], { PATH: path.join(d, 'empty-path') });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /ssh-keygen is not on PATH/);
  noKey(d);
});

test('a trust directory that cannot be written: exit 2, the directory named, nothing written', { skip: process.getuid?.() === 0 && 'root writes anywhere' }, (t) => {
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  fs.mkdirSync(path.join(d, 'trust'), { mode: 0o500 });
  const r = run(d, ['--ssh-key', k]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /trust directory .*trust cannot be written/);
  noKey(d);
});

test('a trust directory holding another key for the role: refused with the conflict named, and left as it was', (t) => {
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  const other = generate('claude-code', { home: path.join(d, 'elsewhere') });
  fs.mkdirSync(path.join(d, 'trust'));
  const theirs = path.join(d, 'trust', 'claude-code.pub');
  fs.copyFileSync(path.join(d, 'elsewhere', 'keys', 'claude-code.pub'), theirs);
  const before = fs.readFileSync(theirs);
  const r = run(d, ['--ssh-key', k]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, new RegExp(`claude-code\\.pub holds ${other.kid}.*never replaced`));
  assert.deepEqual(fs.readFileSync(theirs), before);
  noKey(d);
});

test('an SSH key file that is not a key: exit 2, named as unreadable rather than as a passphrase, nothing written', (t) => {
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  fs.writeFileSync(k, 'not a key\n', { mode: 0o600 });
  const r = run(d, ['--ssh-key', k]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /is not an SSH private key ssh-keygen can read/);
  assert.doesNotMatch(r.stderr, /passphrase/);
  noKey(d);
});

test('a step that fails after the key was made removes that key again', (t) => {
  // the trust directory is writable, but the role's subdirectory in it is taken by a file, so the copy fails after
  // the key and the binding exist; the run must leave the home as it found it
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  fs.mkdirSync(path.join(d, 'trust'));
  fs.writeFileSync(path.join(d, 'trust', 'claude-code'), 'a file where the role directory goes\n');
  const r = spawnSync(process.execPath, [BIN, 'setup', 'claude-code/reviewer', '--principal', 'ana@example.com', '--trust', path.join(d, 'trust'), '--ssh-key', k], {
    env: { ...process.env, AGENTKEY_HOME: path.join(d, 'home') }, encoding: 'utf8', timeout: 20_000,
  });
  assert.equal(r.status, 2, r.stderr);
  for (const f of ['reviewer.key', 'reviewer.pub', 'reviewer.pub.sshsig', 'reviewer.pub.principal']) {
    assert.equal(fs.existsSync(path.join(d, 'home', 'keys', 'claude-code', f)), false, `${f} removed`);
  }
});

test('a role already bound to another principal: refused, and the binding left as it was', (t) => {
  const d = scratch(t);
  const k = sshKey(d, 'id_human', 'ana@example.com');
  assert.equal(run(d, ['--ssh-key', k]).status, 0);
  const sig = path.join(d, 'home', 'keys', 'claude-code.pub.sshsig');
  const before = fs.readFileSync(sig);
  const r = spawnSync(process.execPath, [BIN, 'setup', 'claude-code', '--principal', 'bo@example.com', '--trust', path.join(d, 'trust'), '--ssh-key', k], {
    env: { ...process.env, AGENTKEY_HOME: path.join(d, 'home') }, encoding: 'utf8', timeout: 20_000,
  });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /already bound .*never replaced/);
  assert.deepEqual(fs.readFileSync(sig), before);
});
