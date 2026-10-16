// AK-REV1-AC05 (issue 10): the trust directory's <role>.pub is compared by kid, so the raw base64url form of the same
// key is the same key; another key is still refused
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generate, load } from '../src/index.mjs';
import { setup } from '../src/setup.mjs';

test('the raw form of the same key is accepted and left as it is; another kid is refused', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-trustid-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const key = path.join(d, 'id_human');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'x', '-f', key]);
  const h = path.join(d, 'home'), trust = path.join(d, 'trust');
  const g = generate('ci', { home: h });
  fs.mkdirSync(trust);
  fs.writeFileSync(path.join(trust, 'ci.pub'), `${load('ci', { home: h }).publicKey}\n`);
  const raw = fs.readFileSync(path.join(trust, 'ci.pub'));
  assert.equal(setup('ci', { principal: 'ana@example.com', sshKey: key, trust, home: h }).kid, g.kid);
  assert.deepEqual(fs.readFileSync(path.join(trust, 'ci.pub')), raw, 'the receiver\'s file is kept');

  const other = generate('ci', { home: path.join(d, 'other') });
  const t2 = path.join(d, 'trust2');
  fs.mkdirSync(t2);
  fs.writeFileSync(path.join(t2, 'ci.pub'), `${load('ci', { home: path.join(d, 'other') }).publicKey}\n`);
  assert.throws(() => setup('ci', { principal: 'ana@example.com', sshKey: key, trust: t2, home: h }), (e) => e.code === 'AGENTKEY_CONFLICT' && e.message.includes(other.kid) && e.message.includes(g.kid));
});
