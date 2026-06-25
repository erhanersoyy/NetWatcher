import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reapplyBlocks } from './firewall.js';

// An empty password must short-circuit BEFORE any sudo/pfctl spawn, so this
// test is safe to run in CI with no privileges.
test('reapplyBlocks rejects an empty password without spawning sudo', async () => {
  const r = await reapplyBlocks(['1.2.3.4'], '');
  assert.equal(r.success, false);
  assert.equal(r.applied.length, 0);
  assert.match(r.message ?? '', /password required/i);
});
