// AK-SETUP-AC03: setup runs as a command of bin/agentkey.mjs, and setup --json prints the shape proofline's guided
// setup reads: { ok, role, kid, principal, trust, sign, wrote }. A missing --principal is a usage error (exit 3)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));

test('setup --json as a child process prints role, kid, principal, trust and sign; text mode prints the sign line', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-setup-cli-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const key = path.join(d, 'id_human');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'ana@example.com', '-f', key]);
  const env = { ...process.env, AGENTKEY_HOME: path.join(d, 'home') };
  const trust = path.join(d, 'trust');
  const r = spawnSync(process.execPath, [BIN, 'setup', 'claude-code', '--principal', 'ana@example.com', '--ssh-key', key, '--trust', trust, '--json'], { env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  for (const k of ['role', 'kid', 'principal', 'trust', 'sign']) assert.ok(k in out, `${k} in ${r.stdout}`);
  assert.deepEqual([out.ok, out.role, out.principal, out.trust], [true, 'claude-code', 'ana@example.com', path.resolve(trust)]);
  assert.match(out.kid, /^k[0-9a-f]{16}$/);
  assert.match(out.sign, /^agentkey sign claude-code --type /);

  const again = spawnSync(process.execPath, [BIN, 'setup', 'claude-code', '--principal', 'ana@example.com', '--ssh-key', key, '--trust', trust], { env, encoding: 'utf8' });
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, new RegExp(`^${out.kid} claude-code bound to ana@example.com, trusted in `, 'm'));
  assert.match(again.stdout, /^agentkey sign claude-code --type /m);

  const usage = spawnSync(process.execPath, [BIN, 'setup', 'claude-code', '--ssh-key', key], { env, encoding: 'utf8' });
  assert.equal(usage.status, 3, usage.stderr);
  assert.match(usage.stderr, /setup needs --principal/);
});
