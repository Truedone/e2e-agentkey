// AK-06: the public keys agentkey refuses to trust, ported from hivevault (server/test/key_small_order.test.mjs at
// 3c8d4e2). Eight points of the Ed25519 curve have an order of 1, 2, 4 or 8, and under the identity key the value B
// (the base point) with scalar 1 verifies for every message; node:crypto imports those keys and accepts that value.
// This file proves each of libsodium's seven blocked y values is a point whose order divides 8 with its own curve
// arithmetic, shows the forgery is real, and then feeds every blocked encoding into each way a key enters agentkey:
// kid(), the trusted keys of verifyDSSE, a trust directory read by `agentkey verify --keys`, and bindingMessage
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { kid, publicKeyProblem, verifyDSSE, pae, bindingMessage, generate, load, signDSSE } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));

// ---- the curve, to prove each blocked y is a point of order dividing 8 (8*P is the neutral element) ----
const Pm = (1n << 255n) - 19n;
const mod = (a) => ((a % Pm) + Pm) % Pm;
const modpow = (a, e) => { a = mod(a); let r = 1n; while (e > 0n) { if (e & 1n) r = mod(r * a); a = mod(a * a); e >>= 1n; } return r; };
const inv = (a) => modpow(a, Pm - 2n);
const D = mod(mod(-121665n) * inv(121666n));
function decodePoint(bytes) {
  let y = 0n; for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  y = mod(y);   // a y >= p reduces to y - p: the same point, a second spelling
  const sign = (bytes[31] & 0x80) >> 7;
  const y2 = mod(y * y);
  const x2 = mod(mod(y2 - 1n) * inv(mod(D * y2 + 1n)));
  let x = modpow(x2, (Pm + 3n) / 8n);
  if (mod(x * x) !== x2) x = mod(x * modpow(2n, (Pm - 1n) / 4n));
  if ((x & 1n) !== BigInt(sign)) x = mod(-x);
  return { x, y, z: 1n, t: mod(x * y) };
}
function addPoints(P, Q) {   // twisted Edwards, a = -1, extended coordinates
  const A = mod((P.y - P.x) * (Q.y - Q.x));
  const B = mod((P.y + P.x) * (Q.y + Q.x));
  const C = mod(P.t * 2n * D * Q.t);
  const Dd = mod(P.z * 2n * Q.z);
  const E = mod(B - A), F = mod(Dd - C), G = mod(Dd + C), H = mod(B + A);
  return { x: mod(E * F), y: mod(G * H), t: mod(E * H), z: mod(F * G) };
}
const isNeutral = (P) => mod(P.x) === 0n && mod(P.y - P.z) === 0n;
const times8 = (P) => { const P2 = addPoints(P, P), P4 = addPoints(P2, P2); return addPoints(P4, P4); };

// libsodium's ed25519_ref10 blocklist, each read with the sign bit masked, and the class agentkey gives each
const ROWS = [
  ['y = 0', '0000000000000000000000000000000000000000000000000000000000000000', 'small-order key'],
  ['y = 1 (the identity)', '0100000000000000000000000000000000000000000000000000000000000000', 'small-order key'],
  ['order 8 (a)', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', 'small-order key'],
  ['order 8 (b)', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'small-order key'],
  ['y = p - 1', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'small-order key'],
  ['y = p (a second spelling of 0)', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'non-canonical key'],
  ['y = p + 1 (a second spelling of 1)', 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'non-canonical key'],
];
// the fourteen encodings: each blocked y with the sign bit clear and set
const BLOCKED = ROWS.flatMap(([name, hex, klass]) => [0, 0x80].map((sign) => {
  const b = Buffer.from(hex, 'hex'); b[31] |= sign;
  return { name: `${name}, sign ${sign ? 1 : 0}`, bytes: b, x: b.toString('base64url'), klass };
}));
// the identity public key, and the value that verifies under it for every message (B with scalar 1)
const IDENTITY = Buffer.from('01' + '00'.repeat(31), 'hex');
const UNIV = Buffer.concat([Buffer.from('58' + '66'.repeat(31), 'hex'), Buffer.from('01' + '00'.repeat(31), 'hex')]);
const pemOf = (bytes) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: bytes.toString('base64url') }, format: 'jwk' }).export({ type: 'spki', format: 'pem' });

test('each blocked y is a point whose order divides 8', () => {
  for (const [name, hex] of ROWS) assert.ok(isNeutral(times8(decodePoint(Buffer.from(hex, 'hex')))), name);
});

test('the forgery is real: node:crypto verifies B-with-scalar-1 under the identity key for any message', () => {
  const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: IDENTITY.toString('base64url') }, format: 'jwk' });
  assert.equal(crypto.verify(null, Buffer.from('any message at all'), key, UNIV), true);
});

test('publicKeyProblem names the class of every blocked encoding and lets a fresh key through; kid refuses them in every form', () => {
  for (const k of BLOCKED) {
    assert.equal(publicKeyProblem(k.bytes), k.klass, k.name);
    for (const form of [k.x, k.bytes]) assert.throws(() => kid(form), (e) => e.code === 'AGENTKEY_UNSAFE_KEY' && e.message.includes(k.klass), k.name);
    if (k.klass === 'small-order key') assert.throws(() => kid(pemOf(k.bytes)), (e) => e.code === 'AGENTKEY_UNSAFE_KEY', `${k.name} as PEM`);
  }
  const fresh = crypto.generateKeyPairSync('ed25519').publicKey;
  const x = fresh.export({ format: 'jwk' }).x;
  assert.equal(publicKeyProblem(Buffer.from(x, 'base64url')), null);
  assert.match(kid(x), /^k[0-9a-f]{16}$/);
  // a base64url string that decodes to the same 32 bytes with nonzero padding bits is a second spelling
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const twin = x.slice(0, 42) + alphabet[(alphabet.indexOf(x[42]) & 0x3c) | 0x01];
  assert.notEqual(twin, x);
  assert.equal(Buffer.from(twin, 'base64url').compare(Buffer.from(x, 'base64url')), 0);
  assert.throws(() => kid(twin), (e) => e.code === 'AGENTKEY_UNSAFE_KEY' && /non-canonical/.test(e.message));
  // a y below p that no point of the curve has: y = 2 is the first
  const y2 = Buffer.alloc(32); y2[0] = 2;
  assert.equal(publicKeyProblem(y2), 'not a curve point');
});

test('verifyDSSE does not accept the forgery: the identity key is refused as a trusted key', () => {
  const envelope = { payloadType: 'application/json', payload: Buffer.from('{"forged":true}').toString('base64'), signatures: [{ keyid: '', sig: UNIV.toString('base64') }] };
  // the forgery is a valid signature of this envelope's PAE under the identity key
  const idKey = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: IDENTITY.toString('base64url') }, format: 'jwk' });
  assert.equal(crypto.verify(null, pae(envelope.payloadType, Buffer.from('{"forged":true}')), idKey, UNIV), true);
  for (const form of [IDENTITY.toString('base64url'), IDENTITY, pemOf(IDENTITY), idKey, { kid: 'kanything', publicKey: idKey }, { kid: 'kanything', publicKey: pemOf(IDENTITY) }]) {
    assert.throws(() => verifyDSSE(envelope, [form]), (e) => e.code === 'AGENTKEY_UNSAFE_KEY');
  }
  // and a real key still verifies its own signature
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-so-'));
  try {
    generate('r', { home: h });
    const env2 = signDSSE('text/plain', 'hi', load('r', { home: h }));
    assert.equal(verifyDSSE(env2, [load('r', { home: h }).publicKey]).ok, true);
  } finally { fs.rmSync(h, { recursive: true, force: true }); }
});

test('agentkey verify --keys refuses a trust directory holding a blocked key, naming the file, and binding refuses one too', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-so-trust-'));
  try {
    fs.writeFileSync(path.join(d, 'identity.pub'), pemOf(IDENTITY));
    const envelope = { payloadType: 'application/json', payload: Buffer.from('{"forged":true}').toString('base64'), signatures: [{ keyid: '', sig: UNIV.toString('base64') }] };
    const r = spawnSync(process.execPath, [BIN, 'verify', '--keys', d], { input: JSON.stringify(envelope), encoding: 'utf8' });
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stderr, /identity\.pub: public key .* refused: small-order key/);
    assert.doesNotMatch(r.stdout, /verified/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
  assert.throws(() => bindingMessage(IDENTITY.toString('base64url')), (e) => e.code === 'AGENTKEY_UNSAFE_KEY');
});
