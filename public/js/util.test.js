import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, isPrivateIP, formatBytes, looksLikeIP, isIPv6, isLocalhost, flag, fmtBytes, relTime, formatTime } from './util.js';

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
