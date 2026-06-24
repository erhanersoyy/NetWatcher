import { test } from 'node:test';
import assert from 'node:assert/strict';
import { __testSerialize } from './geolocation.js';

test('serialized operations never overlap', async () => {
  let active = 0;
  let maxActive = 0;
  const op = async () => {
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
  };
  await Promise.all([
    __testSerialize(op),
    __testSerialize(op),
    __testSerialize(op),
  ]);
  assert.equal(maxActive, 1); // strictly one at a time
});
