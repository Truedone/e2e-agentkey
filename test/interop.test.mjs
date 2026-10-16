// AK-02: an envelope signed here verifies with an independent DSSE implementation, the sigstore verifier
// (@sigstore/verify, a devDependency). It runs offline: the bundle carries the public key by its hint (the kid) and
// no transparency-log or timestamp entries, so the verifier is given that key as its only trust material and
// thresholds of zero; what it checks is the DSSE signature itself, over its own PAE
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { bundleFromJSON } from '@sigstore/bundle';
import { Verifier, toSignedEntity } from '@sigstore/verify';
import { generate, load, signDSSE, statement } from '../src/index.mjs';

const bundleOf = (env) => ({
  mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
  verificationMaterial: { publicKey: { hint: env.signatures[0].keyid }, tlogEntries: [], timestampVerificationData: { rfc3161Timestamps: [] } },
  dsseEnvelope: env,
});
// the verifier's trust material: this one public key, found by its hint, and nothing else
const trustOnly = (kid, publicKey) => ({
  certificateAuthorities: [], timestampAuthorities: [], tlogs: [], ctlogs: [],
  publicKey: (hint) => {
    if (hint !== kid) throw new Error(`key not found: ${hint}`);
    return { publicKey, validFor: () => true };
  },
});

test('an envelope signed here verifies with the sigstore verifier, and a tampered one does not', (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-interop-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  generate('claude-code', { home });
  const key = load('claude-code', { home });
  const st = statement([{ name: 'a.tgz', digest: { sha256: 'cd'.repeat(32) } }], 'https://example.com/p/v1', { ok: true });
  const env = signDSSE('application/vnd.in-toto+json', JSON.stringify(st), key);
  const verifier = new Verifier(trustOnly(key.kid, crypto.createPublicKey(key.privateKey)), { tlogThreshold: 0, ctlogThreshold: 0, tsaThreshold: 0 });
  assert.doesNotThrow(() => verifier.verify(toSignedEntity(bundleFromJSON(bundleOf(env)))));
  const tampered = { ...env, payload: Buffer.from(JSON.stringify({ ...st, predicate: { ok: false } })).toString('base64') };
  assert.throws(() => verifier.verify(toSignedEntity(bundleFromJSON(bundleOf(tampered)))), /signature verification failed/);
});
