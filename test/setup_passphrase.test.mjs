// AK-SETUP-AC08: an SSH key that needs a passphrase, with no ssh-agent and no terminal, fails within 10 s with the
// reason named and never waits on ssh-keygen's prompt; nothing is written. The child runs detached, in a session of
// its own, so it has no controlling terminal to open
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));

test('a passphrase key with no agent and no terminal: exit 2 within 10 s, the passphrase named, nothing written', { skip: process.platform === 'win32' && 'no /dev/tty on win32' }, async (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-setup-pass-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const key = path.join(d, 'id_locked');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'correct horse', '-C', 'ana@example.com', '-f', key]);
  const env = { ...process.env, AGENTKEY_HOME: path.join(d, 'home') };
  delete env.SSH_AUTH_SOCK;
  delete env.SSH_ASKPASS;
  const started = Date.now();
  const child = spawn(process.execPath, [BIN, 'setup', 'claude-code', '--principal', 'ana@example.com', '--ssh-key', key, '--trust', path.join(d, 'trust')], {
    env, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (b) => { err += b; });
  const killer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 15_000);
  const status = await new Promise((resolve) => child.on('close', (c, s) => resolve(c ?? s)));
  clearTimeout(killer);
  const took = Date.now() - started;
  assert.ok(took < 10_000, `took ${took} ms`);
  assert.equal(status, 2, err);
  assert.match(err, /needs its passphrase.*ssh-add/);
  assert.equal(fs.existsSync(path.join(d, 'home', 'keys', 'claude-code.key')), false);
  assert.equal(fs.existsSync(path.join(d, 'trust')), false);
});
