// A key record's not_after and verify --at are ISO 8601 dates. Date.parse alone rolls a day that does not exist into
// the next month (2026-02-30 is 2 March) and reads trailing text as a date in another month (2026-02-28junk), so a
// typo moved a key's expiry with no error. Each such value is now refused: --at as a usage error (exit 3), a record's
// not_after as an unreadable key record (exit 2, reason keys); the forms that are dates still verify
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

const NOT_A_DAY = ['2026-02-30', '2026-02-29', '2026-04-31', '2026-02-28junk', '2026-02-28T25:00:00Z', '2026-02-28T12:00:00+24:00'];

test('verify refuses --at on a day that does not exist (exit 3) and a not_after on one (exit 2, keys)', (t) => {
  const root = scratch(t), h = path.join(root, 'home'), trust = path.join(root, 'trust');
  const g = cli(h, ['init', 'codex', '--json']).json();
  fs.mkdirSync(trust);
  const env = cli(h, ['sign', 'codex', '--type', 'text/plain'], 'x').out;
  fs.writeFileSync(path.join(trust, 'codex.json'), JSON.stringify({ publicKey: g.publicKey, not_after: '2030-01-01T00:00:00Z' }));
  for (const at of NOT_A_DAY) assert.equal(cli(h, ['verify', '--keys', trust, '--at', at], env).code, 3, at);
  // the forms that are dates still verify: a day, a time in UTC, an offset, a leap day, a fraction of a second
  for (const at of ['2029-12-31', '2029-12-31T23:59:59Z', '2030-01-01T01:59:59+02:00', '2028-02-29', '2029-12-31T23:59:59.999Z']) {
    assert.equal(cli(h, ['verify', '--keys', trust, '--at', at], env).code, 0, at);
  }
  assert.equal(cli(h, ['verify', '--keys', trust, '--at', '2030-01-01T02:00:01+02:00'], env).code, 2);
  for (const notAfter of NOT_A_DAY) {
    fs.writeFileSync(path.join(trust, 'codex.json'), JSON.stringify({ publicKey: g.publicKey, not_after: notAfter }));
    const v = cli(h, ['verify', '--keys', trust, '--at', '2026-01-01', '--json'], env);
    assert.deepEqual([v.code, v.json().reason], [2, 'keys'], notAfter);
  }
});
