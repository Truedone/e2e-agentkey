// statement(): each subject's digest is a map of algorithm names to digests (in-toto ResourceDescriptor). A digest of
// null passed the typeof check and Object.keys(null) threw a TypeError, and an array passed as a map with keys "0", "1";
// both are refused as every other bad subject is, with AGENTKEY_INVALID
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statement } from '../src/index.mjs';

const TYPE = 'https://example.com/p/v1';

test('a subject whose digest is null, an array, a string or empty is refused with AGENTKEY_INVALID', () => {
  for (const digest of [null, [], ['ab'.repeat(32)], 'ab'.repeat(32), {}]) {
    assert.throws(() => statement([{ name: 'a.tgz', digest }], TYPE, {}), { name: 'AgentkeyError', code: 'AGENTKEY_INVALID' }, JSON.stringify(digest));
  }
  const ok = statement([{ name: 'a.tgz', digest: { sha256: 'ab'.repeat(32) } }], TYPE, {});
  assert.deepEqual(ok.subject, [{ name: 'a.tgz', digest: { sha256: 'ab'.repeat(32) } }]);
});
