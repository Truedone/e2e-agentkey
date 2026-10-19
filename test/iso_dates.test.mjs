// A key record's not_after is an ISO 8601 date. Date.parse alone rolls a day past the end of its month into the next
// month (2026-02-30 is 2 March), so a key whose record said February stayed valid into March. The day is now read as
// the month's last day, and a key past it verifies as expired
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/agentkey.mjs', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-iso-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
const cli = (h, args, input = '') => {
  const env = { ...process.env, AGENTKEY_HOME: h };
  delete env.AGENTKEY_ROLE;
  const r = spawnSync(process.execPath, [BIN, ...args], { input, env, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, json: () => JSON.parse(r.stdout) };
};

test('a not_after past the end of its month is the month\'s last day, so the key expires within that month', (t) => {
  const root = scratch(t), h = path.join(root, 'home'), trust = path.join(root, 'trust');
  const g = cli(h, ['init', 'codex', '--json']).json();
  fs.mkdirSync(trust);
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').out;
  for (const [notAfter, within, after] of [['2026-02-30', '2026-02-27', '2026-03-01'], ['2026-04-31', '2026-04-29', '2026-05-01'], ['2026-02-29T12:00:00Z', '2026-02-28T11:00:00Z', '2026-02-28T13:00:00Z']]) {
    fs.writeFileSync(path.join(trust, 'codex.json'), JSON.stringify({ publicKey: g.publicKey, not_after: notAfter }));
    assert.equal(cli(h, ['verify', '--keys', trust, '--at', within, '--json'], env).json().reason, 'verified', notAfter);
    const v = cli(h, ['verify', '--keys', trust, '--at', after, '--json'], env);
    assert.deepEqual([v.code, v.json().reason], [2, 'expired'], notAfter);
  }
});
