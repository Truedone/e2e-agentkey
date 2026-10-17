// AK-R01-AC01: a role's public key has one source. With B.pub copied over A.pub, pub, list, revoke, bind and the
// agent signer each refuse role A with AGENTKEY_CONFLICT (exit 2, reason conflict) and change nothing under the home:
// revoke never lists B's kid, bind never vouches for B's key. The same holds for a role whose .key was moved into
// ssh-agent (agent-add --remove), where the agent's comment for the key names the role it was added for
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate } from '../src/index.mjs';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const hasAgent = spawnSync('ssh-agent', ['-h']).error?.code !== 'ENOENT';
const run = (args, env, input) => spawnSync(process.execPath, [BIN, ...args], { env, input, encoding: 'utf8', timeout: 30_000 });
const json = (r) => JSON.parse(r.stdout);

// every file under dir with the sha256 of its bytes, so "nothing changed" covers renames, new files and edits
function snapshot(dir) {
  const out = {};
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name);
      if (e.isDirectory()) walk(f);
      else out[path.relative(dir, f)] = crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
    }
  };
  walk(dir);
  return out;
}

function conflict(r, what) {
  assert.equal(r.status, 2, `${what}: ${r.stdout}${r.stderr}`);
  const o = json(r);
  assert.equal(o.ok, false, what);
  assert.equal(o.reason, 'conflict', `${what}: ${r.stdout}`);
}

test('B.pub over A.pub: pub, list, revoke, bind and the agent signer refuse role A and change nothing', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-pub-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const h = path.join(d, 'home');
  const env = { ...process.env, AGENTKEY_HOME: h };
  delete env.AGENTKEY_SIGNER;
  const a = generate('a', { home: h }), b = generate('b', { home: h });

  // before the copy every command acts on A's own key
  assert.equal(json(run(['pub', 'a', '--json'], env)).kid, a.kid);
  const listed = run(['list', '--json'], env);
  assert.equal(listed.status, 0, listed.stderr);
  assert.deepEqual(json(listed).keys.map((k) => [k.role, k.kid]).sort(), [['a', a.kid], ['b', b.kid]]);

  fs.copyFileSync(path.join(h, 'keys', 'b.pub'), path.join(h, 'keys', 'a.pub'));
  const before = snapshot(h);

  const pub = run(['pub', 'a', '--json'], env);
  conflict(pub, 'pub a');
  assert.doesNotMatch(pub.stdout, new RegExp(b.publicKey), 'pub never exports B\'s key for role A');

  const list = run(['list', '--json'], env);
  assert.equal(list.status, 2, list.stdout + list.stderr);
  const lk = Object.fromEntries(json(list).keys.map((k) => [k.role, k]));
  assert.equal(json(list).reason, 'conflict');
  assert.equal(lk.a.kid, null, 'role A is listed without a kid');
  assert.match(lk.a.conflict, new RegExp(`${b.kid}.*${a.kid}`));
  assert.equal(lk.b.kid, b.kid, 'role B is listed as before');
  assert.match(list.stderr, /does not match/);

  conflict(run(['revoke', 'a', '--json'], env), 'revoke a');
  // the SSH key is never reached: the conflict is found before anything is signed
  conflict(run(['bind', 'a', '--principal', 'you@example.com', '--ssh-key', path.join(d, 'no-such-key'), '--json'], env), 'bind a');
  conflict(run(['sign', 'a', '--type', 'text/plain', '--json'], { ...env, AGENTKEY_SIGNER: 'ssh-agent', SSH_AUTH_SOCK: path.join(d, 'no-agent.sock') }, 'x'), 'agent sign a');

  assert.deepEqual(snapshot(h), before, 'nothing under the home changed');
  assert.equal(fs.existsSync(path.join(h, 'keys', 'revoked.txt')), false, 'revoke listed no kid');
});

// the agent's socket gets a short directory of its own: a unix socket path is capped at 104 bytes on macOS (108 on
// Linux), and os.tmpdir() under a long TMPDIR passes that, so the agent would never start
async function startAgent(t, d) {
  const sd = fs.mkdtempSync(path.join(process.platform === 'win32' ? os.tmpdir() : '/tmp', 'akag-'));
  t.after(() => fs.rmSync(sd, { recursive: true, force: true }));
  const sock = path.join(sd, 's'), log = path.join(d, 'askpass.log');
  const askpass = path.join(d, 'askpass.sh');
  fs.writeFileSync(askpass, `#!/bin/sh\necho asked >> "${log}"\necho yes\n`, { mode: 0o755 });
  const agent = spawn('ssh-agent', ['-D', '-a', sock], {
    env: { PATH: process.env.PATH, HOME: d, SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: ':0' }, stdio: 'ignore',
  });
  t.after(() => agent.kill('SIGTERM'));
  for (let i = 0; i < 100 && !fs.existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
  assert.ok(fs.existsSync(sock), 'ssh-agent started');
  return { sock, asked: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).length : 0) };
}

test('keys moved into ssh-agent: B.pub over A.pub is refused by the agent\'s comment, and the agent is never asked to sign', { skip: !hasAgent && 'no ssh-agent' }, async (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-pubagent-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const ag = await startAgent(t, d);
  const h = path.join(d, 'home');
  const env = { ...process.env, AGENTKEY_HOME: h, SSH_AUTH_SOCK: ag.sock, AGENTKEY_SIGNER: 'ssh-agent' };
  const a = generate('a', { home: h }), b = generate('b', { home: h });
  for (const role of ['a', 'b']) assert.equal(run(['agent-add', role, '--remove', '--json'], env).status, 0);
  assert.equal(fs.existsSync(path.join(h, 'keys', 'a.key')), false);

  // before the copy the .pub is accepted: the agent holds that key for role A
  assert.equal(json(run(['pub', 'a', '--json'], env)).kid, a.kid);

  fs.copyFileSync(path.join(h, 'keys', 'b.pub'), path.join(h, 'keys', 'a.pub'));
  const before = snapshot(h);
  const s = run(['sign', 'a', '--type', 'text/plain', '--json'], env, 'x');
  conflict(s, 'agent sign a');
  assert.match(json(s).error, new RegExp(`${b.kid}.*agentkey b `));
  conflict(run(['pub', 'a', '--json'], env), 'pub a');
  conflict(run(['revoke', 'a', '--json'], env), 'revoke a');
  assert.equal(ag.asked(), 0, 'the agent was never asked to sign');
  assert.deepEqual(snapshot(h), before, 'nothing under the home changed');

  // a role whose key is neither on disk nor in the agent is not trusted from its .pub alone
  const noAgent = run(['pub', 'b', '--json'], { ...env, SSH_AUTH_SOCK: path.join(d, 'none.sock') });
  assert.equal(noAgent.status, 2, noAgent.stdout);
  assert.equal(json(noAgent).reason, 'agent');
});
