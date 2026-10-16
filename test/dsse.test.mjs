// AK-02: DSSE sign and verify, and the in-toto Statement builder
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generate, load, pae, signDSSE, verifyDSSE, statement } from '../src/index.mjs';

const vector = JSON.parse(fs.readFileSync(new URL('./vectors/dsse-protocol.json', import.meta.url), 'utf8'));
const b64url32 = (dec) => Buffer.from(BigInt(dec).toString(16).padStart(64, '0'), 'hex').toString('base64url');
const vectorKey = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64url32(vector.key.x), y: b64url32(vector.key.y) }, format: 'jwk' });

const keyFor = (t, role) => {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-dsse-'));
  t.after(() => fs.rmSync(h, { recursive: true, force: true }));
  generate(role, { home: h });
  return load(role, { home: h });
};

test('PAE matches the DSSE protocol test vector', () => {
  assert.equal(pae(vector.payloadType, vector.body).toString('utf8'), vector.pae);
  assert.equal(pae('', '').toString('utf8'), 'DSSEv1 0  0 ');
  // LEN is the byte length, not the character count
  assert.equal(pae('t', 'é').toString('utf8'), 'DSSEv1 1 t 2 é');
});

test('the DSSE protocol test vector envelope verifies with its published P-256 key, and fails when tampered', () => {
  const r = verifyDSSE(vector.envelope, [{ kid: 'dsse-vector', publicKey: vectorKey }]);
  assert.deepEqual([r.ok, r.verified, r.unknown, r.failed], [true, ['dsse-vector'], [], []]);
  assert.equal(r.payload.toString('utf8'), vector.body);
  const tampered = { ...vector.envelope, payload: Buffer.from('hello world!').toString('base64') };
  const t = verifyDSSE(tampered, [{ kid: 'dsse-vector', publicKey: vectorKey }]);
  assert.equal(t.ok, false);
  assert.deepEqual(t.verified, []);
});

test('an envelope signed here verifies, and a tampered payload or type fails for the known key', (t) => {
  const key = keyFor(t, 'claude-code');
  const env = signDSSE('application/vnd.in-toto+json', '{"a":1}', key);
  assert.equal(env.signatures.length, 1);
  assert.equal(env.signatures[0].keyid, key.kid);
  const good = verifyDSSE(env, [key.publicKey]);
  assert.deepEqual([good.ok, good.verified, good.unknown, good.failed], [true, [key.kid], [], []]);
  assert.equal(good.payload.toString('utf8'), '{"a":1}');
  for (const bad of [{ ...env, payload: Buffer.from('{"a":2}').toString('base64') }, { ...env, payloadType: 'text/plain' }]) {
    const r = verifyDSSE(bad, [key.publicKey]);
    assert.deepEqual([r.ok, r.verified, r.unknown, r.failed], [false, [], [], [key.kid]]);
  }
  // URL-safe base64 is accepted as well as standard
  const urlsafe = { ...env, payload: Buffer.from('{"a":1}').toString('base64url'), signatures: [{ ...env.signatures[0], sig: Buffer.from(env.signatures[0].sig, 'base64').toString('base64url') }] };
  assert.equal(verifyDSSE(urlsafe, [key.publicKey]).ok, true);
});

test('an unknown keyid is reported as unknown, not as a failure', (t) => {
  const a = keyFor(t, 'codex'); const b = keyFor(t, 'cursor');
  const r = verifyDSSE(signDSSE('text/plain', 'x', a), [b.publicKey]);
  assert.deepEqual([r.ok, r.verified, r.unknown, r.failed], [false, [], [a.kid], []]);
});

test('a signature that fails for a known key fails the whole result, even beside one that verifies', (t) => {
  const a = keyFor(t, 'gemini-cli'); const b = keyFor(t, 'crewai/worker');
  const env = signDSSE('text/plain', 'x', a);
  const forged = { keyid: b.kid, sig: signDSSE('text/plain', 'y', b).signatures[0].sig };
  const r = verifyDSSE({ ...env, signatures: [...env.signatures, forged] }, [a.publicKey, b.publicKey]);
  assert.deepEqual([r.ok, r.verified, r.unknown, r.failed], [false, [a.kid], [], [b.kid]]);
});

test('a malformed envelope is refused rather than read as unverified', () => {
  for (const bad of [null, {}, { payloadType: 't', payload: 'eA==', signatures: [] }, { payloadType: 't', payload: 'not base64!', signatures: [{ sig: 'eA==' }] }]) {
    assert.throws(() => verifyDSSE(bad, []), { code: 'AGENTKEY_INVALID' });
  }
});

test('statement builds an in-toto Statement v1', () => {
  const s = statement([{ name: 'a.tgz', digest: { sha256: 'ab'.repeat(32) } }], 'https://example.com/p/v1', { ok: true });
  assert.deepEqual(s, { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'a.tgz', digest: { sha256: 'ab'.repeat(32) } }], predicateType: 'https://example.com/p/v1', predicate: { ok: true } });
  assert.throws(() => statement([], 'https://example.com/p/v1', {}), { code: 'AGENTKEY_INVALID' });
  assert.throws(() => statement([{ name: 'a' }], 'https://example.com/p/v1', {}), { code: 'AGENTKEY_INVALID' });
});
