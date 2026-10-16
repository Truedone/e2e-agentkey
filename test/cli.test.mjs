// AK-03: the CLI. Every command runs as a child process of bin/agentkey.mjs with its own AGENTKEY_HOME, plain and with
// --json, and the exit codes are 0 ok, 1 a failed signature, 2 an unknown key or missing input, 3 usage
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { kid, verifyDSSE } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-cli-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
// runs the CLI; env replaces AGENTKEY_HOME and AGENTKEY_ROLE, nothing else of the caller's agentkey settings leaks in
const cli = (h, args, { input, env = {} } = {}) => {
  const base = { ...process.env };
  delete base.AGENTKEY_ROLE; delete base.AGENTKEY_HOME;
  const r = spawnSync(process.execPath, [BIN, ...args], { input: input ?? '', env: { ...base, AGENTKEY_HOME: h, ...env }, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr, json: () => JSON.parse(r.stdout) };
};
// a trust directory holding the given roles' public keys, as `agentkey pub` writes them
const trustOf = (t, h, roles) => {
  const d = path.join(scratch(t), 'trust');
  fs.mkdirSync(d);
  for (const role of roles) fs.writeFileSync(path.join(d, `${role}.pub`), cli(h, ['pub', role]).out);
  return d;
};

test('init creates the role\'s key, defaults the role to AGENTKEY_ROLE then "agent", and a second init reports the same key', (t) => {
  const h = path.join(scratch(t), 'home');
  const a = cli(h, ['init', 'codex']);
  assert.equal(a.code, 0, a.err);
  assert.match(a.out, /^k[0-9a-f]{16} codex created\n$/);
  assert.equal(fs.statSync(path.join(h, 'keys', 'codex.key')).mode & 0o777, 0o600);
  const j = cli(h, ['init', 'codex', '--json']);
  assert.equal(j.code, 0);
  assert.deepEqual(Object.keys(j.json()).sort(), ['created', 'kid', 'ok', 'publicKey', 'role']);
  assert.equal(j.json().created, false, 'an existing key is reported, never replaced');
  assert.equal(j.json().kid, a.out.split(' ')[0]);
  assert.equal(kid(j.json().publicKey), j.json().kid);
  assert.equal(cli(h, ['init', '--json'], { env: { AGENTKEY_ROLE: 'cursor' } }).json().role, 'cursor');
  assert.equal(cli(h, ['init', '--json']).json().role, 'agent');
});

test('list names every role with its kid, a nested role by its "/" path', (t) => {
  const h = path.join(scratch(t), 'home');
  const k1 = cli(h, ['init', 'codex', '--json']).json().kid;
  const k2 = cli(h, ['init', 'crewai/research:lead', '--json']).json().kid;
  const l = cli(h, ['list']);
  assert.equal(l.code, 0, l.err);
  assert.deepEqual(l.out.trim().split('\n').sort(), [`${k1} codex`, `${k2} crewai/research:lead`].sort());
  const j = cli(h, ['list', '--json']);
  assert.equal(j.code, 0);
  assert.deepEqual(j.json(), { ok: true, keys: [{ role: 'codex', kid: k1 }, { role: 'crewai/research:lead', kid: k2 }], revoked: [] });
  assert.deepEqual(cli(path.join(h, 'none'), ['list', '--json']).json(), { ok: true, keys: [], revoked: [] }, 'a home with no keys lists none');
});

test('pub prints the role\'s SPKI PEM, and --json adds its kid and base64url form', (t) => {
  const h = path.join(scratch(t), 'home');
  const g = cli(h, ['init', 'gemini-cli', '--json']).json();
  const p = cli(h, ['pub', 'gemini-cli']);
  assert.equal(p.code, 0, p.err);
  assert.match(p.out, /^-----BEGIN PUBLIC KEY-----\n[\s\S]+-----END PUBLIC KEY-----\n$/);
  assert.equal(kid(p.out), g.kid);
  const j = cli(h, ['pub', 'gemini-cli', '--json']).json();
  assert.deepEqual([j.ok, j.role, j.kid, j.publicKey, j.pem], [true, 'gemini-cli', g.kid, g.publicKey, p.out]);
});

test('sign writes a DSSE envelope of stdin signed by the role\'s key; --json wraps it with the kid', (t) => {
  const h = path.join(scratch(t), 'home');
  const g = cli(h, ['init', 'claude-code', '--json']).json();
  const payload = JSON.stringify({ _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'a', digest: { sha256: '00' } }] });
  const s = cli(h, ['sign', 'claude-code', '--type', 'application/vnd.in-toto+json'], { input: payload });
  assert.equal(s.code, 0, s.err);
  const env = s.json();
  assert.equal(env.payloadType, 'application/vnd.in-toto+json');
  assert.equal(Buffer.from(env.payload, 'base64').toString('utf8'), payload);
  assert.deepEqual(env.signatures.map((x) => x.keyid), [g.kid]);
  assert.equal(verifyDSSE(env, [g.publicKey]).ok, true, 'the library verifies what the CLI signed');
  const j = cli(h, ['sign', 'claude-code', '--type=text/plain', '--json'], { input: 'hello' }).json();
  assert.deepEqual([j.ok, j.role, j.kid, j.envelope.payloadType], [true, 'claude-code', g.kid, 'text/plain']);
});

test('verify exits 0 for a good envelope, 1 for a tampered one and 2 for an unknown key, plain and with --json', (t) => {
  const h = path.join(scratch(t), 'home');
  const g = cli(h, ['init', 'codex', '--json']).json();
  cli(h, ['init', 'stranger']);
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], { input: 'release 1.2.3' }).out;
  const trust = trustOf(t, h, ['codex']);

  const ok = cli(h, ['verify', '--keys', trust], { input: env });
  assert.equal(ok.code, 0, ok.err);
  assert.equal(ok.out, `verified ${g.kid}\n`);
  const okj = cli(h, ['verify', '--keys', trust, '--json'], { input: env }).json();
  assert.deepEqual(okj, { ok: true, reason: 'verified', verified: [g.kid], revoked: [], expired: [], failed: [], unknown: [], payloadType: 'text/plain', payload: Buffer.from('release 1.2.3').toString('base64') });
  // the output of sign --json verifies as it is
  assert.equal(cli(h, ['verify', '--keys', trust], { input: cli(h, ['sign', 'codex', '--type', 'text/plain', '--json'], { input: 'x' }).out }).code, 0);

  const tampered = JSON.stringify({ ...JSON.parse(env), payload: Buffer.from('release 6.6.6').toString('base64') });
  const bad = cli(h, ['verify', '--keys', trust], { input: tampered });
  assert.equal(bad.code, 1);
  assert.equal(bad.out, `failed ${g.kid}\n`);
  assert.deepEqual([cli(h, ['verify', '--keys', trust, '--json'], { input: tampered }).json().reason], ['failed']);

  const other = cli(h, ['sign', 'stranger', '--type', 'text/plain'], { input: 'release 1.2.3' }).out;
  const unk = cli(h, ['verify', '--keys', trust, '--json'], { input: other });
  assert.equal(unk.code, 2);
  assert.equal(unk.json().reason, 'unknown');
  assert.equal(unk.json().ok, false);
});

test('missing input and a missing key exit 2, on every command that needs one, plain and with --json', (t) => {
  const h = path.join(scratch(t), 'home');
  cli(h, ['init', 'codex']);
  const trust = trustOf(t, h, ['codex']);
  for (const [args, input, reason] of [
    [['sign', 'codex', '--type', 'text/plain'], '', 'input'],
    [['verify', '--keys', trust], '', 'input'],
    [['verify', '--keys', trust], 'not json', 'input'],
    [['verify', '--keys', path.join(trust, 'nope')], '{}', 'keys'],
    [['sign', 'nobody', '--type', 'text/plain'], 'x', 'missing'],
    [['pub', 'nobody'], '', 'missing'],
    [['revoke', 'nobody'], '', 'missing'],
  ]) {
    const p = cli(h, args, { input });
    assert.equal(p.code, 2, `${args.join(' ')}: ${p.err}`);
    assert.match(p.err, /^agentkey: /);
    const j = cli(h, [...args, '--json'], { input });
    assert.equal(j.code, 2, args.join(' '));
    assert.deepEqual([j.json().ok, j.json().reason], [false, reason], args.join(' '));
  }
});

test('usage errors exit 3, plain and with --json', (t) => {
  const h = path.join(scratch(t), 'home');
  for (const args of [[], ['bogus'], ['sign', 'codex'], ['sign'], ['pub'], ['revoke'], ['verify'], ['list', 'extra'], ['init', 'a', 'b'], ['verify', '--keys'], ['init', '--colour'], ['verify', '--keys', h, '--at', 'yesterday'], ['init', '../escape']]) {
    const p = cli(h, args);
    assert.equal(p.code, 3, `${args.join(' ')}: ${p.out}${p.err}`);
    if (!args.length) continue;
    const j = cli(h, [...args, '--json']);
    assert.equal(j.code, 3, args.join(' '));
    assert.equal(j.json().ok, false);
  }
  const help = cli(h, ['--help']);
  assert.equal(help.code, 0);
  assert.match(help.out, /^usage: agentkey/);
});

test('a key file with a wide mode is refused when signing, exit 2', (t) => {
  const h = path.join(scratch(t), 'home');
  cli(h, ['init', 'codex']);
  fs.chmodSync(path.join(h, 'keys', 'codex.key'), 0o644);
  const j = cli(h, ['sign', 'codex', '--type', 'text/plain', '--json'], { input: 'x' });
  assert.equal(j.code, 2);
  assert.equal(j.json().reason, 'insecure');
});

test('a trust directory may hold a key as the base64url of its raw bytes', (t) => {
  const h = path.join(scratch(t), 'home');
  const g = cli(h, ['init', 'codex', '--json']).json();
  const d = path.join(scratch(t), 'raw');
  fs.mkdirSync(d);
  fs.writeFileSync(path.join(d, `${g.kid}.pub`), `${g.publicKey}\n`);
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], { input: 'x' }).out;
  assert.equal(cli(h, ['verify', '--keys', d], { input: env }).code, 0);
  // and a key that is not Ed25519 is an error in the directory, not a silent skip
  fs.writeFileSync(path.join(d, 'rsa.pub'), crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' }));
  const j = cli(h, ['verify', '--keys', d, '--json'], { input: env });
  assert.deepEqual([j.code, j.json().reason], [2, 'keys']);
});
