import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, isPrivateIP, formatBytes, looksLikeIP, isIPv6, isLocalhost, flag, fmtBytes, relTime, formatTime, describeBlock, blockRepairStatus, canonicalIP, summarizeProcesses, sampleRate, csvCell } from './util.js';

test('escapeHtml neutralizes HTML', () => {
  assert.equal(escapeHtml('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(escapeHtml('"quoted" & \'single\''), '&quot;quoted&quot; &amp; &#39;single&#39;');
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('isPrivateIP classifies RFC1918 + link-local', () => {
  assert.equal(isPrivateIP('192.168.1.1'), true);
  assert.equal(isPrivateIP('10.0.0.1'), true);
  assert.equal(isPrivateIP('169.254.1.1'), true);
  assert.equal(isPrivateIP('172.16.0.1'), true);
  assert.equal(isPrivateIP('8.8.8.8'), false);
  assert.equal(isPrivateIP('1.1.1.1'), false);
  assert.equal(isPrivateIP(null), false);
});

test('formatBytes scales units', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(999.000999), '999 B');
  assert.equal(formatBytes(1536), '1.5 KB');
  assert.equal(formatBytes(1048576), '1.0 MB');
  assert.equal(formatBytes(null), '-');
  assert.equal(formatBytes(undefined), '-');
});

test('looksLikeIP validates v4/v6', () => {
  assert.equal(looksLikeIP('1.2.3.4'), true);
  assert.equal(looksLikeIP('192.168.1.1'), true);
  assert.equal(looksLikeIP('::1'), true);
  assert.equal(looksLikeIP('not-an-ip'), false);
  assert.equal(looksLikeIP('999.999.999.999'), false);
  assert.equal(looksLikeIP(''), false);
  assert.equal(looksLikeIP('::::'), false);
  assert.equal(looksLikeIP('2001:db8::1::2'), false);
  assert.equal(looksLikeIP('2001:db8::1'), true);
  assert.equal(looksLikeIP('1.2.3.4:443'), false);
});

test('saved blocks never imply verified firewall enforcement', () => {
  const saved = new Set(['203.0.113.10', '203.0.113.11']);
  assert.deepEqual(describeBlock('203.0.113.10', null, saved), { kind: 'unknown', label: 'Saved · unverified' });
  assert.equal(describeBlock('203.0.113.10', new Set(), saved).label, 'Not in firewall table');
  assert.equal(describeBlock('203.0.113.10', new Set(saved), saved, 2).label, 'In firewall table');
  assert.equal(describeBlock('203.0.113.10', null, saved, 2).label, 'Saved · unverified');
  // Aggregate stale counts cannot identify which specific IP is stale.
  assert.equal(describeBlock('203.0.113.10', null, saved, 1).kind, 'unknown');
  assert.equal(describeBlock('203.0.113.10', null, saved, 2, false).kind, 'unknown');
});

test('equivalent IPv6 spellings use the same firewall membership', () => {
  const ip = '2001:db8::abcd', expanded = '2001:0DB8:0:0:0:0:0:ABCD';
  assert.equal(canonicalIP(expanded), ip);
  assert.equal(describeBlock(expanded, new Set([ip]), new Map([[ip, {}]])).kind, 'present');
  assert.equal(canonicalIP('fe80::1%en0'), 'fe80::1%en0');
  assert.equal(canonicalIP('invalid'), 'invalid');
});

test('re-apply guidance follows observed configuration and missing entries, not old boot markers', () => {
  const saved = new Map([['203.0.113.10', { appliedBoot: 1 }]]);
  const healthy = { pfEnabled: true, anchorLinked: true, rulesPresent: true };
  assert.equal(blockRepairStatus(new Set(saved.keys()), saved, healthy), null);
  assert.match(blockRepairStatus(new Set(), saved, healthy).message, /1 saved rules are missing/);
  assert.equal(blockRepairStatus(new Set(saved.keys()), saved, { ...healthy, pfEnabled: false }).urgent, true);
  assert.equal(blockRepairStatus(null, saved, null).urgent, false);
  assert.equal(blockRepairStatus(null, new Map(), null), null);
});

test('summary counts use only the visible process and connection subset', () => {
  const visible = [{ isSystemProcess: false, connections: [
    { state: 'ESTABLISHED', geo: { countryCode: 'TR', isp: 'Example' } },
    { state: 'TIME_WAIT', geo: { countryCode: 'TR', isp: 'Example' } },
    { state: '', geo: null },
  ] }];
  assert.deepEqual(summarizeProcesses(visible), {
    processes: 1, system: 0, user: 1, connections: 3, countries: 1,
    providers: 1, established: 1, timewait: 1, other: 1,
  });
  assert.equal(summarizeProcesses([]).connections, 0);
});

test('sample rates use elapsed time and do not count reconnect baselines as traffic', () => {
  assert.equal(sampleRate(undefined, 10_000_000, 1), 0);
  assert.equal(sampleRate(100, 500, 2), 200);
  assert.equal(sampleRate(100, 500, 10), 40);
  assert.equal(sampleRate(100, 500, 0), 0);
  assert.equal(sampleRate(500, 100, 2), 50);
});

test('CSV metadata stays one cell and cannot become a spreadsheet formula', () => {
  assert.equal(csvCell('Example, "ISP"'), '"Example, ""ISP"""');
  assert.equal(csvCell('=1+1'), '"\'=1+1"');
  assert.equal(csvCell(null), '""');
});

test('isIPv6 detects colons', () => {
  assert.equal(isIPv6('::1'), true);
  assert.equal(isIPv6('2001:db8::1'), true);
  assert.equal(isIPv6('1.2.3.4'), false);
  assert.equal(isIPv6(null), false);
});

test('isLocalhost detects loopback addresses', () => {
  assert.equal(isLocalhost('127.0.0.1'), true);
  assert.equal(isLocalhost('::1'), true);
  assert.equal(isLocalhost('127.0.0.2'), true);
  assert.equal(isLocalhost('192.168.1.1'), false);
});

test('flag returns emoji for valid country code', () => {
  assert.equal(flag(''), '');
  assert.equal(flag('LO'), '');
  assert.equal(flag('??'), '');
  // US flag: regional indicator U + S
  assert.equal(flag('US'), '🇺🇸');
});

test('fmtBytes formats GB and MB', () => {
  assert.match(fmtBytes(1073741824), /1\.0 GB/);
  assert.match(fmtBytes(5368709120), /5\.0 GB/);
  assert.match(fmtBytes(1048576), /1 MB/);
  assert.equal(fmtBytes(null), '—');
  assert.equal(fmtBytes(undefined), '—');
});

test('relTime formats relative timestamps', () => {
  const now = Date.now();
  assert.match(relTime(now - 5000), /5s ago/);
  assert.match(relTime(now - 90000), /\dm ago/);
  assert.match(relTime(now - 7200000), /\dh ago/);
  assert.match(relTime(now - 172800000), /\dd ago/);
});

test('formatTime formats timestamps as YYYY-MM-DD HH:MM:SS', () => {
  assert.equal(formatTime(0), '-');
  assert.equal(formatTime(null), '-');
  // Just check the format pattern
  assert.match(formatTime(new Date('2024-01-15T10:30:45').getTime()), /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
});

test('table membership does not mask disabled PF or missing rules', () => {
  const table = new Set(['203.0.113.1']), saved = new Map([['203.0.113.1', {}]]);
  assert.deepEqual(describeBlock('203.0.113.1', table, saved, 0, true, { pfEnabled: false }), { kind: 'pending', label: 'In table · PF disabled' });
  assert.equal(describeBlock('203.0.113.1', table, saved, 0, true, { pfEnabled: true, anchorLinked: false }).kind, 'pending');
  assert.equal(describeBlock('203.0.113.1', table, saved, 0, true, { pfEnabled: null }).kind, 'unknown');
});
