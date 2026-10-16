// AK-06: trailer(kid, runId) gives the two lines a commit made by an agent role carries, and git reads them back as
// trailers; anything that could open a third trailer or break the block is refused
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { trailer } from '../src/index.mjs';

test('trailer gives the Agent-Key and Agent-Run lines, and git interpret-trailers reads exactly those two', () => {
  const t = trailer('k0123456789abcdef', 'run-42');
  assert.equal(t, 'Agent-Key: k0123456789abcdef\nAgent-Run: run-42');
  const msg = `fix: something\n\nThe body.\n\n${t}\n`;
  const parsed = execFileSync('git', ['interpret-trailers', '--parse'], { input: msg, encoding: 'utf8' });
  assert.equal(parsed, 'Agent-Key: k0123456789abcdef\nAgent-Run: run-42\n');
});

test('a kid that is not k and 16 hex, or a run id with a space, a line break or nothing in it, is refused', () => {
  for (const bad of ['k0123', 'K0123456789abcdef', 'k0123456789ABCDEF', 'k0123456789abcdef\nX: y', '', null]) {
    assert.throws(() => trailer(bad, 'run-1'), (e) => e.code === 'AGENTKEY_INVALID', String(bad));
  }
  for (const bad of ['', 'run 1', 'run-1\nSigned-off-by: someone', 'run-1\r', 'x'.repeat(201), 42]) {
    assert.throws(() => trailer('k0123456789abcdef', bad), (e) => e.code === 'AGENTKEY_INVALID', JSON.stringify(bad));
  }
});
