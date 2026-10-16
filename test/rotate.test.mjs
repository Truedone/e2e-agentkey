// TB-05-AC02: rotate gives the role a new key and a rotation statement signed by the old one. A receiver whose trust
// directory holds the old public key and the statement accepts the new kid; the old key expires at the rotation
// date; a statement the old key did not sign, a tampered one, or one from a revoked key vouches for nothing
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate, load, signDSSE, rotate } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const verify = (trust, envelope, at) => spawnSync(process.execPath, [BIN, 'verify', '--keys', trust, ...(at ? ['--at', at] : []), '--json'], { input: JSON.stringify(envelope), encoding: 'utf8' });
const setupRotation = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-rotate-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const h = path.join(d, 'home'), trust = path.join(d, 'trust');
  const g = generate('ci', { home: h });
  fs.mkdirSync(path.join(trust, 'rotations'), { recursive: true });
  fs.copyFileSync(path.join(h, 'keys', 'ci.pub'), path.join(trust, 'ci.pub'));
  const before = signDSSE('text/plain', 'signed before the rotation', load('ci', { home: h }));
  const r = rotate('ci', { home: h, now: Date.parse('2026-10-16T12:00:00Z') });
  return { d, h, trust, g, before, r };
};

test('rotate makes a new key, keeps the old one, and the receiver accepts the new kid through the statement', (t) => {
  const { h, trust, g, before, r } = setupRotation(t);
  assert.equal(r.old, g.kid);
  assert.notEqual(r.new, g.kid);
  assert.equal(load('ci', { home: h }).kid, r.new, 'the role now signs with the new key');
  assert.ok(fs.existsSync(path.join(h, 'rotated', `${g.kid}.key`)), 'the old key is kept under rotated/');
  const after = signDSSE('text/plain', 'signed after the rotation', load('ci', { home: h }));

  // without the statement the receiver does not know the new kid
  const unknown = verify(trust, after);
  assert.equal(unknown.status, 2);
  assert.equal(JSON.parse(unknown.stdout).reason, 'unknown');
  // with it, the new kid is accepted
  fs.copyFileSync(r.file, path.join(trust, 'rotations', path.basename(r.file)));
  const ok = verify(trust, after);
  assert.equal(ok.status, 0, ok.stdout);
  assert.deepEqual(JSON.parse(ok.stdout).verified, [r.new]);
  // and the old key expires at the rotation date: valid before it, expired after it
  assert.equal(verify(trust, before, '2026-10-16T11:59:59Z').status, 0);
  const late = verify(trust, before, '2026-10-16T12:00:01Z');
  assert.equal(late.status, 2);
  assert.equal(JSON.parse(late.stdout).reason, 'expired');
});

test('a chain of two rotations is followed in any file order', (t) => {
  const { h, trust, r } = setupRotation(t);
  const r2 = rotate('ci', { home: h, now: Date.parse('2026-10-17T12:00:00Z') });
  // name the second statement so it sorts first
  fs.copyFileSync(r2.file, path.join(trust, 'rotations', `a-${path.basename(r2.file)}`));
  fs.copyFileSync(r.file, path.join(trust, 'rotations', `b-${path.basename(r.file)}`));
  const env = signDSSE('text/plain', 'third key', load('ci', { home: h }));
  const v = verify(trust, env);
  assert.equal(v.status, 0, v.stdout);
  assert.deepEqual(JSON.parse(v.stdout).verified, [r2.new]);
});

test('a statement the old key did not sign, a tampered one, or one from a revoked key vouches for nothing', (t) => {
  const { d, h, trust, r } = setupRotation(t);
  const after = signDSSE('text/plain', 'after', load('ci', { home: h }));
  const st = JSON.parse(fs.readFileSync(r.file, 'utf8'));

  // naming the trusted old key but signed by another: the directory is refused, the new kid never verified
  generate('stranger', { home: path.join(d, 'other') });
  const forged = signDSSE('application/vnd.agentkey.rotation+json', Buffer.from(st.payload, 'base64'), load('stranger', { home: path.join(d, 'other') }));
  fs.writeFileSync(path.join(trust, 'rotations', 'forged.rotation.dsse'), JSON.stringify(forged));
  const fv = verify(trust, after);
  assert.equal(fv.status, 2);
  assert.match(fv.stdout, /does not verify under/);
  fs.rmSync(path.join(trust, 'rotations', 'forged.rotation.dsse'));
  // a statement naming an old key the receiver does not hold vouches for nothing: the new kid stays unknown
  const orphan = JSON.parse(Buffer.from(st.payload, 'base64'));
  const sOther = generate('s2', { home: path.join(d, 'other3') });
  const orphanEnv = signDSSE('application/vnd.agentkey.rotation+json', JSON.stringify({ ...orphan, old: sOther.kid }), load('s2', { home: path.join(d, 'other3') }));
  fs.writeFileSync(path.join(trust, 'rotations', 'orphan.rotation.dsse'), JSON.stringify(orphanEnv));
  assert.equal(JSON.parse(verify(trust, after).stdout).reason, 'unknown');
  fs.rmSync(path.join(trust, 'rotations', 'orphan.rotation.dsse'));

  // tampered: the old key's signature kept, the payload changed to name another key; the directory is refused
  const other = generate('x', { home: path.join(d, 'other2') });
  const body = JSON.parse(Buffer.from(st.payload, 'base64'));
  const tampered = { ...st, payload: Buffer.from(JSON.stringify({ ...body, new: other.kid, publicKey: other.publicKey })).toString('base64') };
  fs.writeFileSync(path.join(trust, 'rotations', 'tampered.rotation.dsse'), JSON.stringify(tampered));
  const tv = verify(trust, after);
  assert.equal(tv.status, 2);
  assert.match(tv.stderr + tv.stdout, /does not verify under/);
  fs.rmSync(path.join(trust, 'rotations', 'tampered.rotation.dsse'));

  // the old key revoked: its statement no longer vouches for the new kid
  fs.copyFileSync(r.file, path.join(trust, 'rotations', path.basename(r.file)));
  fs.writeFileSync(path.join(trust, 'revoked.txt'), `${r.old} 2026-10-16T13:00:00Z\n`);
  assert.equal(JSON.parse(verify(trust, after).stdout).reason, 'unknown');
});

test('agentkey rotate on the command line prints the new kid and the statement to share', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-rotate-cli-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const env = { ...process.env, AGENTKEY_HOME: path.join(d, 'home') };
  assert.equal(spawnSync(process.execPath, [BIN, 'init', 'ci'], { env }).status, 0);
  const r = spawnSync(process.execPath, [BIN, 'rotate', 'ci', '--json'], { env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.match(out.new, /^k[0-9a-f]{16}$/);
  assert.ok(fs.existsSync(out.file));
  assert.match(path.basename(out.file), new RegExp(`^${out.old}-${out.new}\\.rotation\\.dsse$`));
});
