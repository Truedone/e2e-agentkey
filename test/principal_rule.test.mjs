// AK-REV1-AC04 (issue 9): a principal is one exact allowed_signers entry. The field is a pattern list, so a comment,
// a list, a quote, a leading -, whitespace and the wildcards * and ? are refused by setup and by bind before anything is
// written; an accepted principal's binding verifies
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generate, bind, verifyBinding, keyPaths } from '../src/index.mjs';
import { setup } from '../src/setup.mjs';
import { checkPrincipal } from '../src/bind.mjs';

const BAD = ['#broken', 'foo,bar', '"quoted"', "it's", '-I', 'a*b', '*@example.com', 'ana@example.?om', 'ana example', 'ana\tx', '', 'x'.repeat(257), '!negated'];
const GOOD = ['ana@example.com', 'ci-bot', 'first.last+agent@example.co.uk', 'A_1'];

test('the rule refuses every form OpenSSH reads as something other than one exact entry', () => {
  for (const p of BAD) assert.throws(() => checkPrincipal(p), (e) => e.code === 'AGENTKEY_PRINCIPAL', JSON.stringify(p));
  for (const p of GOOD) assert.doesNotThrow(() => checkPrincipal(p), p);
});

test('setup and bind refuse a bad principal before writing; a good one binds and verifies', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-principal-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const key = path.join(d, 'id_human');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'x', '-f', key]);
  const h = path.join(d, 'home'), trust = path.join(d, 'trust');
  for (const p of ['*@example.com', 'foo,bar', '#c']) {
    assert.throws(() => setup('ci', { principal: p, sshKey: key, trust, home: h }), (e) => e.code === 'AGENTKEY_PRINCIPAL', p);
  }
  assert.equal(fs.existsSync(h), false);
  assert.equal(fs.existsSync(trust), false);
  generate('ci', { home: h });
  assert.throws(() => bind('ci', key, '*@example.com', { home: h }), (e) => e.code === 'AGENTKEY_PRINCIPAL');
  assert.equal(fs.existsSync(`${keyPaths('ci', { home: h }).pub}.sshsig`), false);
  for (const p of GOOD) {
    const hp = path.join(d, `h-${GOOD.indexOf(p)}`), tp = path.join(d, `t-${GOOD.indexOf(p)}`);
    setup('ci', { principal: p, sshKey: key, trust: tp, home: hp });
    assert.equal(verifyBinding(path.join(tp, 'ci.pub'), path.join(tp, 'allowed_signers')).status, 'bound', p);
  }
});
