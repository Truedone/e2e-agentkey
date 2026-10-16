// TB-05-AC01: AGENTKEY_SIGNER=ssh-agent signs through the agent, and each signature asks for a confirmation. A throwaway
// ssh-agent runs with SSH_ASKPASS pointed at a script that records each question and answers from a control file, so
// the test sees the confirmation happen per signature, and sees a declined one fail the signing. The file signer is
// the default and says so
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate, load, verifyDSSE } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const hasAgent = spawnSync('ssh-agent', ['-h']).error?.code !== 'ENOENT';

async function startAgent(t, d) {
  const sock = path.join(d, 'agent.sock'), log = path.join(d, 'askpass.log'), answer = path.join(d, 'answer');
  const askpass = path.join(d, 'askpass.sh');
  fs.writeFileSync(answer, 'yes\n');
  // OpenSSH's agent treats an empty answer or "yes" from askpass, with exit 0, as a confirmation; a non-zero exit as no.
  // One fixed line per call: the agent's prompt spans two lines, so logging it would count each call twice
  fs.writeFileSync(askpass, `#!/bin/sh\necho asked >> "${log}"\n[ "$(cat "${answer}")" = yes ] || exit 1\necho yes\n`, { mode: 0o755 });
  const agent = spawn('ssh-agent', ['-D', '-a', sock], {
    env: { PATH: process.env.PATH, HOME: d, SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: ':0' }, stdio: 'ignore',
  });
  t.after(() => agent.kill('SIGTERM'));
  for (let i = 0; i < 100 && !fs.existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
  assert.ok(fs.existsSync(sock), 'ssh-agent started');
  return { sock, log, answer, asked: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).length : 0) };
}
const run = (args, env, input) => spawnSync(process.execPath, [BIN, ...args], { env, input, encoding: 'utf8', timeout: 30_000 });

test('the file signer is the default and the result says signer: file', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-signer-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const env = { ...process.env, AGENTKEY_HOME: path.join(d, 'home') };
  delete env.AGENTKEY_SIGNER;
  assert.equal(run(['init', 'ci'], env).status, 0);
  const r = run(['sign', 'ci', '--type', 'text/plain', '--json'], env, 'hello');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).signer, 'file');
});

test('through ssh-agent: each signature is confirmed, verifies under the role key and says signer: ssh-agent; a declined one fails', { skip: !hasAgent && 'no ssh-agent' }, async (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-agent-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const a = await startAgent(t, d);
  const h = path.join(d, 'home');
  const env = { ...process.env, AGENTKEY_HOME: h, SSH_AUTH_SOCK: a.sock, AGENTKEY_SIGNER: 'ssh-agent' };
  const g = generate('claude-code', { home: h });
  const pub = load('claude-code', { home: h }).publicKey;

  const add = run(['agent-add', 'claude-code', '--remove', '--json'], env);
  assert.equal(add.status, 0, add.stderr);
  assert.equal(fs.existsSync(path.join(h, 'keys', 'claude-code.key')), false, 'the key file is gone once the agent holds the key');
  assert.equal(a.asked(), 0, 'adding the key asks nothing');

  for (const n of [1, 2]) {
    const s = run(['sign', 'claude-code', '--type', 'application/json', '--json'], env, `{"n":${n}}`);
    assert.equal(s.status, 0, s.stderr);
    const out = JSON.parse(s.stdout);
    assert.equal(out.signer, 'ssh-agent');
    assert.equal(out.kid, g.kid);
    assert.deepEqual(verifyDSSE(out.envelope, [pub]).verified, [g.kid]);
    assert.equal(a.asked(), n, `one confirmation per signature (${n})`);
  }

  fs.writeFileSync(a.answer, 'no\n');
  const no = run(['sign', 'claude-code', '--type', 'application/json'], env, '{"n":3}');
  assert.equal(no.status, 2, no.stdout + no.stderr);
  assert.match(no.stderr, /refused to sign .*confirmation was declined/);
  assert.equal(a.asked(), 3);
});

test('with no agent on SSH_AUTH_SOCK the ssh-agent signer fails with the reason, never falls back to a file', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-noagent-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const h = path.join(d, 'home');
  generate('ci', { home: h });
  const env = { ...process.env, AGENTKEY_HOME: h, AGENTKEY_SIGNER: 'ssh-agent', SSH_AUTH_SOCK: path.join(d, 'nothing.sock') };
  const r = run(['sign', 'ci', '--type', 'text/plain'], env, 'x');
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /no ssh-agent answers on/);
  const unset = { ...env }; delete unset.SSH_AUTH_SOCK;
  assert.match(run(['sign', 'ci', '--type', 'text/plain'], unset, 'x').stderr, /SSH_AUTH_SOCK is not set/);
});
