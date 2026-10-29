import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recordBlock, recordUnblock, markReapplied, getBlockHistory, countStaleBlocks } from './block-store.js';
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
  assert.equal((await stat(join(dir, 'blocks.json'))).mode & 0o777, 0o600);
  await recordBlock('2.2.2.2', { country: null }, 50);
  let active = (await getBlockHistory()).active;
  assert.equal(active.find((r) => r.ip === '1.1.1.1')?.appliedBoot, 50);

  await markReapplied(['1.1.1.1'], 77);
  active = (await getBlockHistory()).active;
  assert.equal(active.find((r) => r.ip === '1.1.1.1')?.appliedBoot, 77);
  assert.equal(active.find((r) => r.ip === '2.2.2.2')?.appliedBoot, 50);
});

test('legacy IPv6 aliases cannot survive unblock and be restored by re-apply', async () => {
  const expanded = '2001:0DB8:0:0:0:0:0:ABCD', ip = '2001:db8::abcd';
  const legacy = { ...rec(expanded, 50), blockedAt: 1 };
  await writeFile(join(dir, 'blocks.json'), JSON.stringify({
    active: { [expanded]: legacy }, history: [{ ip: expanded, action: 'block', at: 1, country: null }],
  }));
  await markReapplied([ip], 77);
  assert.equal((await getBlockHistory()).active[0].appliedBoot, 77);
  await recordBlock(ip, { country: null }, 77);
  assert.deepEqual((await getBlockHistory()).active.map(row => row.ip), [expanded]);
  // Older stores could contain both spellings. Unblock must remove both.
  const store = await getBlockHistory();
  await writeFile(join(dir, 'blocks.json'), JSON.stringify({
    active: { [expanded]: store.active[0], [ip]: rec(ip, 50) }, history: store.history,
  }));
  await recordUnblock(ip);
  const result = await getBlockHistory();
  assert.deepEqual(result.active, []);
  assert.deepEqual(new Set(result.history.filter(row => row.action === 'unblock').map(row => row.ip)), new Set([expanded, ip]));
});
