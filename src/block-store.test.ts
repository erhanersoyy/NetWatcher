import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recordBlock, markReapplied, getBlockHistory, countStaleBlocks } from './block-store.js';
import type { BlockRecord } from './types.js';

// storePath() reads NETWATCHER_DATA_DIR lazily, so pointing it at a temp dir
// keeps these tests off the real data/blocks.json.
let dir: string;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'nw-store-'));
  process.env.NETWATCHER_DATA_DIR = dir;
});
after(async () => {
  delete process.env.NETWATCHER_DATA_DIR;
  await rm(dir, { recursive: true, force: true });
});

const rec = (ip: string, appliedBoot: number | null): BlockRecord =>
  ({ ip, country: null, blockedAt: 0, appliedBoot });

test('countStaleBlocks: empty active -> 0', () => {
  assert.equal(countStaleBlocks([], 100), 0);
});

test('countStaleBlocks: all applied this boot -> 0', () => {
  assert.equal(countStaleBlocks([rec('1.1.1.1', 100), rec('2.2.2.2', 100)], 100), 0);
});

test('countStaleBlocks: previous-boot and undefined markers count as stale', () => {
  const active = [rec('1.1.1.1', 100), rec('2.2.2.2', 99), { ip: '3.3.3.3', country: null, blockedAt: 0 }];
  assert.equal(countStaleBlocks(active, 100), 2);
});

test('recordBlock persists appliedBoot; markReapplied updates only named IPs', async () => {
  await recordBlock('1.1.1.1', { country: null }, 50);
  await recordBlock('2.2.2.2', { country: null }, 50);
  let active = (await getBlockHistory()).active;
  assert.equal(active.find((r) => r.ip === '1.1.1.1')?.appliedBoot, 50);

  await markReapplied(['1.1.1.1'], 77);
  active = (await getBlockHistory()).active;
  assert.equal(active.find((r) => r.ip === '1.1.1.1')?.appliedBoot, 77);
  assert.equal(active.find((r) => r.ip === '2.2.2.2')?.appliedBoot, 50);
});
