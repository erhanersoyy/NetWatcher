import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFirewall, isBlockableIP, reapplyBlocks } from './firewall.js';
import type { BlockRecord } from './types.js';

function fixture() {
  const state = { enabled: true, linked: true, rules: true, unreadable: false, failCleanup: false, failStore: false, failEnable: false };
  const table = new Set<string>();
  const active = new Map<string, BlockRecord>();
  const calls: string[][] = [];
  const writes: string[] = [];
  let beforeWrite = async () => {};
  const fw = createFirewall({
    authenticate: async () => { calls.push(['authenticate']); },
    pf: async args => {
      calls.push(args);
      if (state.unreadable) throw new Error('permission denied');
      if (args[0] === '-k') { if (state.failCleanup) throw new Error('state cleanup denied'); return ''; }
      if (args[0] === '-e') { if (state.failEnable) throw new Error('cannot enable PF'); state.enabled = true; return ''; }
      if (args[0] === '-s') return args[1] === 'info' ? `Status: ${state.enabled ? 'Enabled' : 'Disabled'}` : state.linked ? 'anchor "com.apple/*" all' : '';
      if (args.includes('-f')) { state.rules = true; return ''; }
      if (args.includes('rules')) return state.rules ? 'block drop out quick from any to <netwatcher_block>\nblock drop in quick from <netwatcher_block> to any' : '';
      const action = args[args.indexOf('-T') + 1], ip = args.at(-1)!;
      if (action === 'add') table.add(ip);
      if (action === 'delete') table.delete(ip);
      return action === 'show' ? [...table].join('\n') : '';
    },
    recordBlock: async (ip, _meta, boot) => {
      await beforeWrite();
      if (state.failStore) throw new Error('disk full');
      writes.push(`block ${ip}`);
      active.set(ip, { ip, country: null, blockedAt: 1, appliedBoot: boot });
    },
    recordUnblock: async ip => {
      if (state.failStore) throw new Error('disk full');
      writes.push(`unblock ${ip}`); active.delete(ip);
    },
    markReapplied: async (ips, boot) => { for (const ip of ips) if (active.has(ip)) active.get(ip)!.appliedBoot = boot; },
    getBlockHistory: async () => ({ active: [...active.values()], history: [] }),
    getBootId: async () => 123,
  });
  return { fw, state, table, active, calls, writes, delayWrite: (fn: () => Promise<void>) => { beforeWrite = fn; } };
}

test('invalid password/IP never authenticates or invokes PF', async () => {
  const f = fixture();
  assert.equal((await reapplyBlocks('')).success, false);
  for (const ip of ['127.9.1.2', '0:0:0:0:0:0:0:1', '::ffff:7f00:1', '::ffff:127.0.0.1', 'invalid']) {
    assert.equal(isBlockableIP(ip), false);
    assert.equal((await f.fw.blockIP(ip, 'dummy')).success, false);
  }
  assert.equal((await f.fw.blockIP('203.0.113.1', 'x\ny')).success, false);
  assert.deepEqual(f.calls, []);
});

for (const [ip, all] of [['203.0.113.1', '0.0.0.0/0'], ['2001:db8::1', '::/0']]) {
  test(`${ip}: block and reapply clean both source and destination states`, async () => {
    const f = fixture();
    assert.equal((await f.fw.blockIP(ip, 'dummy')).success, true);
    assert.deepEqual(f.calls.filter(args => args[0] === '-k'), [['-k', ip], ['-k', all, '-k', ip]]);
    assert.equal(f.active.get(ip)?.appliedBoot, 123);
    f.calls.length = 0;
    assert.equal((await f.fw.reapplyBlocks('dummy')).success, true);
    assert.deepEqual(f.calls.filter(args => args[0] === '-k'), [['-k', ip], ['-k', all, '-k', ip]]);
    assert.equal(f.writes.length, 1, 'reapply must not manufacture new history');
  });
}

test('cleanup failure reports partial change, still tries both directions and does not stamp applied boot', async () => {
  const f = fixture(); f.state.failCleanup = true;
  const result = await f.fw.blockIP('203.0.113.1', 'dummy');
  assert.equal(result.success, false); assert.equal(result.partial, true);
  assert.deepEqual(result.stages, { tableUpdated: true, stateCleanup: false, persisted: true });
  assert.equal(f.calls.filter(args => args[0] === '-k').length, 2);
  assert.equal(f.active.get('203.0.113.1')?.appliedBoot, null);
  assert.equal(result.trafficVerified, false);
});

test('persistence failure is not reported as success after a live table change', async () => {
  const f = fixture(); f.state.failStore = true;
  const result = await f.fw.blockIP('203.0.113.1', 'dummy');
  assert.equal(result.success, false); assert.equal(result.stages?.tableUpdated, true);
  assert.equal(result.stages?.stateCleanup, true); assert.equal(result.stages?.persisted, false);
  assert.match(result.message, /saved state/);
  const unblocked = await f.fw.unblockIP('203.0.113.1', 'dummy');
  assert.equal(unblocked.success, false); assert.equal(unblocked.stages?.tableUpdated, true);
});

test('delayed block write cannot resurrect an unblocked rule; reapply reads desired state inside the queue', async () => {
  const f = fixture();
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { entered = resolve; });
  f.delayWrite(async () => { entered(); await gate; });
  const block = f.fw.blockIP('203.0.113.1', 'dummy');
  await started;
  const unblock = f.fw.unblockIP('203.0.113.1', 'dummy');
  const reapply = f.fw.reapplyBlocks('dummy');
  assert.equal(f.calls.filter(args => args[0] === 'authenticate').length, 1);
  release();
  assert.equal((await block).success, true); assert.equal((await unblock).success, true);
  assert.deepEqual((await reapply).applied, []);
  assert.deepEqual(f.writes, ['block 203.0.113.1', 'unblock 203.0.113.1']);
  assert.equal(f.active.size, 0); assert.equal(f.table.size, 0);
});

test('every operation rechecks rules; disabling PF does not look like an empty healthy table', async () => {
  const f = fixture();
  await f.fw.blockIP('203.0.113.1', 'dummy');
  f.state.enabled = false; f.state.rules = false;
  const status = await f.fw.getFirewallStatus();
  assert.equal(status.pfEnabled, false); assert.deepEqual(status.tableIPs, ['203.0.113.1']);
  assert.equal((await f.fw.blockIP('203.0.113.2', 'dummy')).success, true);
  assert.ok(f.calls.some(args => args.includes('-e'))); assert.ok(f.calls.some(args => args.includes('-f')));
  f.state.enabled = false; f.state.failEnable = true;
  assert.equal((await f.fw.blockIP('203.0.113.3', 'dummy')).success, false);
  assert.equal(f.table.has('203.0.113.3'), false);
});

test('missing anchor reference or unreadable state prevents mutations', async () => {
  const f = fixture(); f.state.linked = false;
  assert.equal((await f.fw.blockIP('203.0.113.1', 'dummy')).success, false);
  assert.equal(f.table.size, 0);
  f.state.unreadable = true;
  const status = await f.fw.getFirewallStatus();
  assert.equal(status.pfEnabled, null); assert.equal(status.tableIPs, null);
  assert.equal(status.rulesPresent, null); assert.equal(status.errors.length, 4);
});

test('unblock removes a saved rule even after PF is disabled or its anchor disappears; it never enables PF', async () => {
  const f = fixture();
  await f.fw.blockIP('203.0.113.1', 'dummy');
  f.state.enabled = false; f.state.linked = false; f.state.rules = false; f.table.clear(); f.calls.length = 0;
  assert.equal((await f.fw.unblockIP('203.0.113.1', 'dummy')).success, true);
  assert.equal(f.active.size, 0);
  assert.equal(f.state.enabled, false);
  assert.equal(f.calls.some(args => args.includes('-e') || args.includes('-f')), false);
});

test('expanded IPv6 can be blocked then removed using its compressed spelling', async () => {
  const f = fixture();
  const expanded = '2001:0DB8:0:0:0:0:0:ABCD', ip = '2001:db8::abcd';
  assert.equal((await f.fw.blockIP(expanded, 'dummy')).success, true);
  assert.deepEqual([...f.table], [ip]);
  assert.deepEqual([...f.active.keys()], [ip]);
  assert.equal((await f.fw.unblockIP(ip, 'dummy')).success, true);
  assert.equal(f.table.size, 0);
  assert.equal(f.active.size, 0);
  assert.deepEqual((await f.fw.reapplyBlocks('dummy')).applied, []);
});
