// AK-01: generate, load, kid, key files mode 0600
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generate, load, kid, home, keyPaths } from '../src/index.mjs';

const tmpHome = (t) => {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-test-'));
  t.after(() => fs.rmSync(h, { recursive: true, force: true }));
  return h;
};

// RFC 8032 section 7.1, TEST 1 public key. The kid is hivevault's replicaIdForKey (server/src/crdt.mjs) of its
// base64url form, computed there and pasted here
const FIXTURE_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const FIXTURE_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const FIXTURE_KID = 'k21fe31dfa154a261';

test('generate then load round-trips: same kid and public key, and the loaded key signs for the .pub', (t) => {
  const h = tmpHome(t);
  const g = generate('claude-code', { home: h });
  assert.match(g.kid, /^k[0-9a-f]{16}$/);
  const p = keyPaths('claude-code', { home: h });
  assert.equal(p.key, path.join(h, 'keys', 'claude-code.key'));
  assert.equal(fs.statSync(p.key).mode & 0o777, 0o600);
  assert.match(fs.readFileSync(p.key, 'utf8'), /^-----BEGIN PRIVATE KEY-----\n/);
  const l = load('claude-code', { home: h });
  assert.equal(l.kid, g.kid);
  assert.equal(l.publicKey, g.publicKey);
  assert.equal(kid(fs.readFileSync(p.pub, 'utf8')), g.kid);
  const msg = Buffer.from('agentkey round trip');
  assert.ok(crypto.verify(null, msg, crypto.createPublicKey(fs.readFileSync(p.pub, 'utf8')), crypto.sign(null, msg, l.privateKey)));
});

test('AGENTKEY_HOME overrides the home, and a role with "/" is a directory under keys/', (t) => {
  const h = tmpHome(t);
  const was = process.env.AGENTKEY_HOME;
  process.env.AGENTKEY_HOME = h;
  t.after(() => { if (was === undefined) delete process.env.AGENTKEY_HOME; else process.env.AGENTKEY_HOME = was; });
  const g = generate('claude-code/subagent:reviewer');
  const file = path.join(h, 'keys', 'claude-code', 'subagent:reviewer.key');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(load('claude-code/subagent:reviewer').kid, g.kid);
});

test('kid matches the hivevault scheme for a fixture public key, in every form it is given', () => {
  assert.equal(kid(Buffer.from(FIXTURE_HEX, 'hex')), FIXTURE_KID);
  assert.equal(kid(FIXTURE_X), FIXTURE_KID);
  const ko = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: FIXTURE_X }, format: 'jwk' });
  assert.equal(kid(ko), FIXTURE_KID);
  assert.equal(kid(ko.export({ type: 'spki', format: 'pem' })), FIXTURE_KID);
  assert.equal(`k${crypto.createHash('sha256').update(Buffer.from(FIXTURE_X, 'base64url')).digest('hex').slice(0, 16)}`, FIXTURE_KID);
  assert.throws(() => kid(Buffer.alloc(31)), { code: 'AGENTKEY_INVALID' });
});

test('a 0644 key file is refused with AGENTKEY_INSECURE, and so is a symbolic link to a 0600 one', (t) => {
  const h = tmpHome(t);
  const g = generate('codex', { home: h });
  const p = keyPaths('codex', { home: h });
  fs.chmodSync(p.key, 0o644);
  assert.throws(() => load('codex', { home: h }), { code: 'AGENTKEY_INSECURE', message: /mode 0644/ });
  fs.chmodSync(p.key, 0o600);
  assert.equal(load('codex', { home: h }).kid, g.kid);
  generate('cursor', { home: h });
  const q = keyPaths('cursor', { home: h });
  fs.rmSync(q.key);
  fs.symlinkSync(p.key, q.key);
  assert.throws(() => load('cursor', { home: h }), { code: 'AGENTKEY_INSECURE' });
});

test('a missing key is AGENTKEY_MISSING, an existing key is never replaced, a role cannot leave keys/', (t) => {
  const h = tmpHome(t);
  assert.throws(() => load('gemini-cli', { home: h }), { code: 'AGENTKEY_MISSING' });
  const g = generate('gemini-cli', { home: h });
  assert.throws(() => generate('gemini-cli', { home: h }), { code: 'AGENTKEY_EXISTS' });
  assert.equal(load('gemini-cli', { home: h }).kid, g.kid);
  for (const bad of ['', '..', 'a/../b', '/abs', 'a//b', 'a\\b', 'a\nb', 'crewai/']) {
    assert.throws(() => keyPaths(bad, { home: h }), { code: 'AGENTKEY_ROLE' }, JSON.stringify(bad));
  }
});

test('on win32 the default home is %APPDATA%/agentkey, AGENTKEY_HOME still overrides, and ":" is written %3A', () => {
  const env = { APPDATA: 'C:\\Users\\dev\\AppData\\Roaming' };
  assert.equal(home({ env, platform: 'win32' }), 'C:\\Users\\dev\\AppData\\Roaming\\agentkey');
  assert.equal(home({ env: { ...env, AGENTKEY_HOME: 'D:\\keys' }, platform: 'win32' }), 'D:\\keys');
  assert.equal(keyPaths('claude-code/subagent:reviewer', { env, platform: 'win32' }).key,
    'C:\\Users\\dev\\AppData\\Roaming\\agentkey\\keys\\claude-code\\subagent%3Areviewer.key');
  assert.equal(home({ env: { XDG_CONFIG_HOME: '/xdg' }, platform: 'linux' }), '/xdg/agentkey');
  assert.equal(home({ env: { XDG_CONFIG_HOME: 'relative' }, platform: 'linux' }), path.posix.join(os.homedir(), '.config', 'agentkey'));
});
