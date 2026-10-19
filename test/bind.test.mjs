// AK-04: binding an agent key to the human's SSH signing key with ssh-keygen -Y. Each test makes a throwaway ed25519
// SSH key and an allowed_signers file naming it
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate, keyPaths, bind, verifyBinding, bindingMessage } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-bind-test-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
// a throwaway ed25519 SSH key with no passphrase, and an allowed_signers line for it under the agentkey namespace
const sshKey = (dir, name, principal) => {
  const f = path.join(dir, name);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', principal, '-f', f]);
  const [type, blob] = fs.readFileSync(`${f}.pub`, 'utf8').trim().split(' ');
  return { key: f, line: `${principal} namespaces="agentkey" ${type} ${blob}\n` };
};
const setup = (t) => {
  const d = scratch(t), h = path.join(d, 'home');
  const human = sshKey(d, 'id_human', 'ana@example.com');
  const allowed = path.join(d, 'allowed_signers');
  fs.writeFileSync(allowed, human.line);
  return { d, h, human, allowed };
};

test('a bound key verifies against the allowed_signers file; a key with no signature is unbound, not invalid', (t) => {
  const { d, h, human, allowed } = setup(t);
  const g = generate('claude-code', { home: h });
  const b = bind('claude-code', human.key, 'ana@example.com', { home: h });
  const pub = keyPaths('claude-code', { home: h }).pub;
  assert.deepEqual([b.kid, b.sig, b.principalFile], [g.kid, `${pub}.sshsig`, `${pub}.principal`]);
  assert.match(fs.readFileSync(b.sig, 'utf8'), /^-----BEGIN SSH SIGNATURE-----\n/);
  assert.ok(fs.readFileSync(b.principalFile, 'utf8').includes('ana'));
  assert.deepEqual(verifyBinding(pub, allowed), { status: 'bound', kid: g.kid, principal: 'ana@example.com' });
  assert.equal(verifyBinding(pub, allowed, 'ana@example.com').status, 'bound');

  // OpenSSH itself verifies the stored signature over the documented message, with nothing of agentkey in the way
  const ok = spawnSync('ssh-keygen', ['-Y', 'verify', '-n', 'agentkey', '-I', 'ana@example.com', '-f', allowed, '-s', b.sig], { input: `${g.publicKey}\n` });
  assert.equal(ok.status, 0, String(ok.stderr));
  assert.deepEqual(bindingMessage(fs.readFileSync(pub, 'utf8')), Buffer.from(`${g.publicKey}\n`));

  generate('codex', { home: h });
  const u = verifyBinding(keyPaths('codex', { home: h }).pub, allowed);
  assert.equal(u.status, 'unbound');
  assert.equal(u.kid.startsWith('k'), true);
});

test('a tampered signature, another principal, a key the file does not allow and a swapped agent key are invalid', (t) => {
  const { d, h, human, allowed } = setup(t);
  generate('claude-code', { home: h });
  const b = bind('claude-code', human.key, 'ana@example.com', { home: h });
  const pub = keyPaths('claude-code', { home: h }).pub;
  const good = fs.readFileSync(b.sig, 'utf8');

  // one base64 character of the signature body changed
  const lines = good.split('\n');
  const i = lines.length - 3;
  lines[i] = lines[i].slice(0, 10) + (lines[i][10] === 'A' ? 'B' : 'A') + lines[i].slice(11);
  fs.writeFileSync(b.sig, lines.join('\n'));
  const tampered = verifyBinding(pub, allowed);
  assert.equal(tampered.status, 'invalid', JSON.stringify(tampered));
  assert.ok(tampered.reason, 'ssh-keygen says why');
  fs.writeFileSync(b.sig, 'not a signature\n');
  assert.equal(verifyBinding(pub, allowed).status, 'invalid');
  fs.writeFileSync(b.sig, good);
  assert.equal(verifyBinding(pub, allowed).status, 'bound');

  assert.equal(verifyBinding(pub, allowed, 'bo@example.com').status, 'invalid', 'a principal the signer is not');

  // signed by an SSH key the allowed_signers file does not name
  const other = sshKey(d, 'id_other', 'ana@example.com');
  bind('claude-code', other.key, 'ana@example.com', { home: h });
  assert.equal(verifyBinding(pub, allowed).status, 'invalid');
  bind('claude-code', human.key, 'ana@example.com', { home: h });
  assert.equal(verifyBinding(pub, allowed).status, 'bound');

  // the agent's .pub replaced by another key: the signature beside it no longer covers it
  const h2 = path.join(d, 'home2');
  generate('claude-code', { home: h2 });
  fs.copyFileSync(keyPaths('claude-code', { home: h2 }).pub, pub);
  assert.equal(verifyBinding(pub, allowed).status, 'invalid');
});

test('the allowed_signers namespace is honoured: a line limited to another namespace does not bind', (t) => {
  const { d, h, human } = setup(t);
  generate('claude-code', { home: h });
  bind('claude-code', human.key, 'ana@example.com', { home: h });
  const gitOnly = path.join(d, 'allowed_git');
  fs.writeFileSync(gitOnly, human.line.replace('namespaces="agentkey"', 'namespaces="git"'));
  assert.equal(verifyBinding(keyPaths('claude-code', { home: h }).pub, gitOnly).status, 'invalid');
});

test('bind refuses a missing role, a missing SSH key and a principal with whitespace', (t) => {
  const { d, h, human } = setup(t);
  assert.throws(() => bind('nobody', human.key, 'ana@example.com', { home: h }), { code: 'AGENTKEY_MISSING' });
  generate('claude-code', { home: h });
  assert.throws(() => bind('claude-code', path.join(d, 'no-such-key'), 'ana@example.com', { home: h }), { code: 'AGENTKEY_MISSING' });
  assert.throws(() => bind('claude-code', human.key, 'ana smith', { home: h }), { code: 'AGENTKEY_PRINCIPAL' });
  assert.throws(() => bind('claude-code', human.key, '', { home: h }), { code: 'AGENTKEY_PRINCIPAL' });
});

test('ssh-keygen is what signs: with no ssh-keygen on PATH, bind throws AGENTKEY_SSH_UNAVAILABLE', (t) => {
  const { h, human } = setup(t);
  generate('claude-code', { home: h });
  const was = process.env.PATH;
  process.env.PATH = path.join(scratch(t), 'empty');
  try {
    assert.throws(() => bind('claude-code', human.key, 'ana@example.com', { home: h }), { code: 'AGENTKEY_SSH_UNAVAILABLE' });
  } finally { process.env.PATH = was; }
});

test('agentkey bind <role> --principal <id> --ssh-key <path> binds, with --json, and its errors keep the exit codes', (t) => {
  const { h, human, allowed } = setup(t);
  const env = { ...process.env, AGENTKEY_HOME: h };
  const cli = (args) => spawnSync(process.execPath, [BIN, ...args], { env, encoding: 'utf8', input: '' });
  assert.equal(cli(['init', 'cursor']).status, 0);
  const r = cli(['bind', 'cursor', '--principal', 'ana@example.com', '--ssh-key', human.key, '--json']);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const j = JSON.parse(r.stdout);
  assert.deepEqual([j.ok, j.role, j.principal], [true, 'cursor', 'ana@example.com']);
  assert.equal(verifyBinding(keyPaths('cursor', { home: h }).pub, allowed).status, 'bound');
  const plain = cli(['bind', 'cursor', '--principal', 'ana@example.com', '--ssh-key', human.key]);
  assert.equal(plain.status, 0, plain.stderr);
  assert.match(plain.stdout, /^k[0-9a-f]{16} cursor bound to ana@example.com\n$/);
  assert.equal(cli(['bind', 'cursor', '--ssh-key', human.key]).status, 3, 'no --principal');
  assert.equal(cli(['bind', '--principal', 'ana@example.com']).status, 3, 'no role');
  assert.equal(cli(['bind', 'nobody', '--principal', 'ana@example.com', '--ssh-key', human.key]).status, 2);
  assert.equal(cli(['bind', 'cursor', '--principal', 'ana smith', '--ssh-key', human.key]).status, 3);
  // revoke takes the binding along with the key, so a new key for the role starts unbound
  assert.equal(cli(['revoke', 'cursor']).status, 0);
  for (const ext of ['key', 'pub', 'pub.sshsig', 'pub.principal']) assert.ok(fs.existsSync(path.join(h, 'revoked', `${j.kid}.${ext}`)), ext);
  assert.equal(verifyBinding(path.join(h, 'revoked', `${j.kid}.pub`), allowed).status, 'bound', 'the moved binding still verifies for the old key');
  assert.equal(cli(['init', 'cursor']).status, 0);
  assert.equal(verifyBinding(keyPaths('cursor', { home: h }).pub, allowed).status, 'unbound');
});
