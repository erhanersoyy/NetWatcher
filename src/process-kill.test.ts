import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIdentities } from './process-identity.js';
import { killProcess } from './process-kill.js';

test('identity includes path with spaces, owner, parent and start time; stale/reused PID cannot be signalled', async () => {
  const identities = parseIdentities('  42  1  501 Thu Oct 29 07:35:40 2026 /Applications/Example Browser.app/Contents/MacOS/Browser\n');
  const identity = identities.get(42)!;
  assert.equal(identity.executable, '/Applications/Example Browser.app/Contents/MacOS/Browser');
  assert.equal(identity.parentPid, 1); assert.equal(identity.uid, 501);
  let signals = 0;
  const deps = { identities: async () => identities, uid: () => 501, selfPid: 100, kill: () => { signals++; return true; } };
  assert.equal((await killProcess(42, undefined, deps)).success, false);
  assert.equal((await killProcess(42, 'a'.repeat(64), deps)).success, false);
  assert.equal((await killProcess(1, identity.token, deps)).success, false);
  assert.equal((await killProcess(100, identity.token, deps)).success, false);
  assert.equal((await killProcess(42, identity.token, { ...deps, uid: () => 502 })).success, false);
  assert.equal(signals, 0);
  assert.equal((await killProcess(42, identity.token, deps)).success, true);
  assert.equal(signals, 1);
  const changed = parseIdentities('42 1 501 Thu Oct 29 07:35:41 2026 /Applications/Example Browser.app/Contents/MacOS/Browser');
  assert.equal((await killProcess(42, identity.token, { ...deps, identities: async () => changed })).success, false);
  assert.equal(signals, 1);
});
