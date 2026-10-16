// AK-REV1-AC02 (issue 7): setup reuses a role's public key only when its private key is there and is that key's pair
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generate } from '../src/index.mjs';
import { setup } from '../src/setup.mjs';

const prep = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-pair-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const key = path.join(d, 'id_human');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'ana@example.com', '-f', key]);
  return { d, h: path.join(d, 'home'), trust: path.join(d, 'trust'), key };
};

test('a public key with no private key is refused and nothing is written', (t) => {
  const { h, trust, key } = prep(t);
  generate('ci', { home: h });
  fs.rmSync(path.join(h, 'keys', 'ci.key'));
  assert.throws(() => setup('ci', { principal: 'ana@example.com', sshKey: key, trust, home: h }), (e) => e.code === 'AGENTKEY_MISSING' && /no private key/.test(e.message));
  assert.equal(fs.existsSync(trust), false);
  assert.equal(fs.existsSync(path.join(h, 'keys', 'ci.pub.sshsig')), false);
});

test('a private key that is not the public key\'s pair is refused and nothing is written', (t) => {
  const { d, h, trust, key } = prep(t);
  generate('ci', { home: h });
  generate('ci', { home: path.join(d, 'other') });
  fs.copyFileSync(path.join(d, 'other', 'keys', 'ci.pub'), path.join(h, 'keys', 'ci.pub'));
  assert.throws(() => setup('ci', { principal: 'ana@example.com', sshKey: key, trust, home: h }), (e) => e.code === 'AGENTKEY_CONFLICT' && /does not match/.test(e.message));
  assert.equal(fs.existsSync(trust), false);
});

test('a matching pair is reused', (t) => {
  const { h, trust, key } = prep(t);
  const g = generate('ci', { home: h });
  assert.equal(setup('ci', { principal: 'ana@example.com', sshKey: key, trust, home: h }).kid, g.kid);
});
