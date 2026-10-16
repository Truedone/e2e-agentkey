// AK-REV1-AC06 (issue 11): whether a passphrase can be asked on a terminal uses stdin's tty flag first, and opens
// /dev/tty only on POSIX, since Windows has none and ssh-keygen reads the console there
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canAskOnTerminal } from '../src/setup.mjs';

const opened = () => { let n = 0; return { fn: () => { n++; }, refuse: () => { n++; throw Object.assign(new Error('ENXIO'), { code: 'ENXIO' }); }, count: () => n }; };

test('Windows: a console on stdin can ask, no console cannot, and /dev/tty is never opened', () => {
  const o = opened();
  assert.equal(canAskOnTerminal({ platform: 'win32', stdinIsTTY: true, openTty: o.fn }), true);
  assert.equal(canAskOnTerminal({ platform: 'win32', stdinIsTTY: false, openTty: o.fn }), false);
  assert.equal(o.count(), 0);
});

test('POSIX: a terminal on stdin can ask; otherwise the controlling terminal decides', () => {
  const o = opened();
  assert.equal(canAskOnTerminal({ platform: 'linux', stdinIsTTY: true, openTty: o.refuse }), true);
  assert.equal(o.count(), 0, 'the flag answers first');
  assert.equal(canAskOnTerminal({ platform: 'darwin', stdinIsTTY: false, openTty: o.fn }), true);
  assert.equal(canAskOnTerminal({ platform: 'linux', stdinIsTTY: false, openTty: o.refuse }), false);
  assert.equal(o.count(), 2);
});
