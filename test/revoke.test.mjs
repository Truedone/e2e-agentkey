// AK-03: revocation and not_after. revoke moves the role's key to revoked/ and appends "<kid> <iso date>" to
// keys/revoked.txt; verify then exits 2 with reason "revoked". A key record carrying not_after verifies a signature
// as expired, exit 2, when the time verify checks at (--at, else now) is after it
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-revoke-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
const cli = (h, args, input = '') => {
  const env = { ...process.env, AGENTKEY_HOME: h };
  delete env.AGENTKEY_ROLE;
  const r = spawnSync(process.execPath, [BIN, ...args], { input, env, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr, json: () => JSON.parse(r.stdout) };
};

test('revoke moves the key to revoked/, lists its kid with the date, and verify then exits 2 with reason revoked', (t) => {
  const root = scratch(t), h = path.join(root, 'home');
  const g = cli(h, ['init', 'codex', '--json']).json();
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], 'release 1.2.3').out;
  // verified against the role's own keys directory before, revoked after
  assert.equal(cli(h, ['verify', '--keys', path.join(h, 'keys')], env).code, 0);

  const r = cli(h, ['revoke', 'codex', '--json']);
  assert.equal(r.code, 0, r.err);
  assert.equal(r.json().kid, g.kid);
  const lines = fs.readFileSync(path.join(h, 'keys', 'revoked.txt'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 1);
  const [k, date] = lines[0].split(' ');
  assert.equal(k, g.kid);
  assert.ok(Math.abs(Date.parse(date) - Date.now()) < 60_000, `an ISO date of now: ${date}`);
  assert.equal(date, new Date(Date.parse(date)).toISOString());
  assert.equal(fs.existsSync(path.join(h, 'keys', 'codex.key')), false, 'the key left keys/');
  assert.equal(fs.statSync(path.join(h, 'revoked', `${g.kid}.key`)).mode & 0o777, 0o600, 'and kept its mode in revoked/');
  assert.ok(fs.existsSync(path.join(h, 'revoked', `${g.kid}.pub`)));

  const v = cli(h, ['verify', '--keys', path.join(h, 'keys'), '--json'], env);
  assert.equal(v.code, 2);
  assert.deepEqual([v.json().ok, v.json().reason, v.json().revoked], [false, 'revoked', [g.kid]]);
  const plain = cli(h, ['verify', '--keys', path.join(h, 'keys')], env);
  assert.deepEqual([plain.code, plain.out], [2, `revoked ${g.kid}\n`]);
  assert.equal(cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').code, 2, 'a revoked role no longer signs');
  assert.deepEqual(cli(h, ['list', '--json']).json().revoked, [{ kid: g.kid, date }]);

  // a new key for the role is a new kid; the old one stays revoked and the new one verifies
  const g2 = cli(h, ['init', 'codex', '--json']).json();
  assert.notEqual(g2.kid, g.kid);
  assert.equal(cli(h, ['verify', '--keys', path.join(h, 'keys')], cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').out).code, 0);
  assert.equal(cli(h, ['verify', '--keys', path.join(h, 'keys')], env).code, 2);
  assert.equal(cli(h, ['revoke', 'codex']).code, 0, 'revoking the second key does not collide with the first in revoked/');
  assert.equal(fs.readFileSync(path.join(h, 'keys', 'revoked.txt'), 'utf8').trim().split('\n').length, 2);
});

test('a revoked kid in a trust directory that still holds its key verifies as revoked, not verified', (t) => {
  const root = scratch(t), h = path.join(root, 'home'), trust = path.join(root, 'trust');
  const g = cli(h, ['init', 'codex', '--json']).json();
  fs.mkdirSync(trust);
  fs.writeFileSync(path.join(trust, 'codex.pub'), cli(h, ['pub', 'codex']).out);
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').out;
  assert.equal(cli(h, ['verify', '--keys', trust], env).code, 0);
  fs.writeFileSync(path.join(trust, 'revoked.txt'), `# revoked keys\n\n${g.kid} 2026-10-16T00:00:00.000Z\n`);
  const v = cli(h, ['verify', '--keys', trust, '--json'], env);
  assert.deepEqual([v.code, v.json().reason, v.json().verified, v.json().revoked], [2, 'revoked', [], [g.kid]]);
  // a tampered envelope from a revoked key still fails as a bad signature, exit 1
  const tampered = JSON.stringify({ ...JSON.parse(env), payload: Buffer.from('y').toString('base64') });
  assert.equal(cli(h, ['verify', '--keys', trust], tampered).code, 1);
  // a good signature from another trusted key is not spoiled by a stray signature naming the revoked kid
  cli(h, ['init', 'cursor']);
  fs.writeFileSync(path.join(trust, 'cursor.pub'), cli(h, ['pub', 'cursor']).out);
  fs.rmSync(path.join(trust, 'codex.pub'));
  const good = JSON.parse(cli(h, ['sign', 'cursor', '--type', 'text/plain'], 'x').out);
  good.signatures.push({ keyid: g.kid, sig: Buffer.alloc(64).toString('base64') });
  assert.equal(cli(h, ['verify', '--keys', trust], JSON.stringify(good)).code, 0);
});

test('not_after: a key record verifies before it, verifies as expired after it (exit 2), and --at picks the time', (t) => {
  const root = scratch(t), h = path.join(root, 'home'), trust = path.join(root, 'trust');
  const g = cli(h, ['init', 'codex', '--json']).json();
  fs.mkdirSync(trust);
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').out;
  fs.writeFileSync(path.join(trust, 'codex.json'), JSON.stringify({ kid: g.kid, publicKey: g.publicKey, not_after: '2030-01-01T00:00:00Z' }));
  const before = cli(h, ['verify', '--keys', trust, '--at', '2029-12-31T23:59:59Z', '--json'], env);
  assert.deepEqual([before.code, before.json().reason], [0, 'verified']);
  const after = cli(h, ['verify', '--keys', trust, '--at', '2030-01-01T00:00:01Z', '--json'], env);
  assert.deepEqual([after.code, after.json().reason, after.json().expired], [2, 'expired', [g.kid]]);
  assert.deepEqual([cli(h, ['verify', '--keys', trust, '--at', '2030-01-01T00:00:01Z'], env).out], [`expired ${g.kid}\n`]);
  // without --at the time is now, and a not_after in the past expires the key
  fs.writeFileSync(path.join(trust, 'codex.json'), JSON.stringify({ publicKey: g.publicKey, not_after: '2020-01-01' }));
  assert.equal(cli(h, ['verify', '--keys', trust, '--json'], env).json().reason, 'expired');
  // a .pub for the same key beside the record does not lift its not_after
  fs.writeFileSync(path.join(trust, 'codex.pub'), cli(h, ['pub', 'codex']).out);
  assert.equal(cli(h, ['verify', '--keys', trust, '--json'], env).json().reason, 'expired');
  // revoked outranks expired
  fs.writeFileSync(path.join(trust, 'revoked.txt'), `${g.kid} 2019-06-01T00:00:00.000Z\n`);
  assert.equal(cli(h, ['verify', '--keys', trust, '--json'], env).json().reason, 'revoked');
});

test('a key record that cannot be read is an error in the trust directory, exit 2, never a key without a limit', (t) => {
  const root = scratch(t), h = path.join(root, 'home'), trust = path.join(root, 'trust');
  const g = cli(h, ['init', 'codex', '--json']).json();
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').out;
  fs.mkdirSync(trust);
  for (const rec of [{ publicKey: g.publicKey, not_after: 'next year' }, { publicKey: g.publicKey, kid: 'k0000000000000000' }, { not_after: '2030-01-01' }]) {
    fs.writeFileSync(path.join(trust, 'codex.json'), JSON.stringify(rec));
    const v = cli(h, ['verify', '--keys', trust, '--json'], env);
    assert.deepEqual([v.code, v.json().reason], [2, 'keys'], JSON.stringify(rec));
  }
  fs.writeFileSync(path.join(trust, 'codex.json'), '{');
  assert.equal(cli(h, ['verify', '--keys', trust], env).code, 2);
});
