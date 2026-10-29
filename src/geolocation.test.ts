import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { createEnrichmentService, isPrivateIP, isPublicIP, normalizeIP } from './geolocation.js';

const location = (ip = '8.8.8.8', extra = {}) => ({ ip, success: true, country: 'Example', country_code: 'EX',
  city: 'Example city', latitude: 0, longitude: 0, connection: { isp: 'Example ISP' }, ...extra });
const response = (value: unknown, status = 200, headers = {}) => new Response(JSON.stringify(value), { status, headers });
const offline = { fetch: async () => { throw new Error('No network'); }, reverse: async () => [] };
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { resolve, promise }; };
async function settle<T extends { state: string }>(read: () => T): Promise<T> {
  for (let i = 0; i < 500; i++) {
    const result = read();
    if (result.state !== 'pending') return result;
    await setImmediate();
  }
  assert.fail('Lookup did not settle');
}

test('public IP: HTTPS, deduplication, TTL and validation', async t => {
  const gate = deferred(); let calls = 0, now = 1000;
  const service = createEnrichmentService({ ...offline, now: () => now, fetch: async (url, options) => {
    calls++; assert.equal(url, 'https://api64.ipify.org?format=json');
    assert.equal(options?.redirect, 'error'); assert.ok(options?.signal);
    await gate.promise; return response({ ip: '8.8.8.8' });
  } });
  t.after(() => { gate.resolve(); service.shutdown(); });
  const a = service.publicIP(), b = service.publicIP(); gate.resolve();
  assert.deepEqual(await Promise.all([a, b]), ['8.8.8.8', '8.8.8.8']);
  assert.equal(calls, 1);
  await service.publicIP(true); assert.equal(calls, 1);
  now += 5 * 60_000; await service.publicIP(); assert.equal(calls, 2);
});

test('public IP failure and quota backoff are not bypassed by forced refresh', async t => {
  let calls = 0, now = 1000;
  const service = createEnrichmentService({ ...offline, now: () => now, fetch: async () => {
    calls++; return response({}, 429, { 'Retry-After': '3600' });
  } });
  t.after(() => service.shutdown());
  assert.equal(await service.publicIP(), null);
  now += 31_000; assert.equal(await service.publicIP(true), null); assert.equal(calls, 1);
  now += 3600_000; await service.publicIP(); assert.equal(calls, 2);
  const invalid = createEnrichmentService({ ...offline, fetch: async () => response({ ip: '127.0.0.1' }) });
  try { assert.equal(await invalid.publicIP(), null); } finally { invalid.shutdown(); }
});

test('local/reserved/invalid addresses never reach geo or DNS; IPv6 aliases normalize', async t => {
  let calls = 0;
  const service = createEnrichmentService({ fetch: async () => { calls++; throw new Error(); }, reverse: async () => { calls++; return []; } });
  t.after(() => service.shutdown());
  for (const ip of ['192.168.1.1', '10.0.0.1', '172.31.0.1', 'FE80::1', 'fe90::1', 'fd00::1', '100.64.0.1',
    '::ffff:127.0.0.1', '::ffff:c0a8:101', '::1']) {
    assert.equal(isPrivateIP(ip), true); assert.equal(service.geo(ip).value?.country, 'Local'); service.domain(ip);
  }
  for (const ip of ['bad', 'example.com/a', '8.8.8.8?x=y', '203.0.113.1', '2001:db8::1', '224.0.0.1', '255.255.255.255', 'fe80::1%en0']) {
    assert.equal(isPublicIP(ip), false); assert.equal(service.geo(ip).value, null); service.domain(ip);
  }
  assert.equal(calls, 0);
  assert.equal(normalizeIP('2001:4860:4860:0000:0000:0000:0000:8888'), '2001:4860:4860::8888');
  assert.equal(normalizeIP('::FFFF:0808:0808'), '8.8.8.8');
});

test('geo: background lookup, shared IPv6 cache and valid zero coordinates', async t => {
  const gate = deferred(); let calls = 0;
  const service = createEnrichmentService({ ...offline, fetch: async url => {
    calls++; const parsed = new URL(String(url));
    assert.equal(parsed.origin, 'https://ipwho.is');
    await gate.promise; return response(location(decodeURIComponent(parsed.pathname.slice(1))));
  } });
  t.after(() => { gate.resolve(); service.shutdown(); });
  assert.equal(service.geo('2001:4860:4860::8888').state, 'pending');
  assert.equal(service.geo('2001:4860:4860:0:0:0:0:8888').state, 'pending');
  assert.equal(calls, 1);
  gate.resolve();
  const result = await settle(() => service.geo('2001:4860:4860::8888'));
  assert.equal(result.state, 'ready'); assert.equal(result.value?.lat, 0); assert.equal(result.value?.lon, 0);
  assert.equal(calls, 1);
});

test('malformed, mismatched and oversized geo responses are unavailable, not invented coordinates', async t => {
  for (const value of [location('1.1.1.1'), location('8.8.8.8', { latitude: '40' }),
    location('8.8.8.8', { longitude: 181 }), location('8.8.8.8', { latitude: null }),
    location('8.8.8.8', { country: 'x'.repeat(20_000) }), { success: false, message: 'Reserved range' }]) {
    const service = createEnrichmentService({ ...offline, fetch: async () => response(value) });
    t.after(() => service.shutdown());
    const result = await settle(() => service.geo('8.8.8.8'));
    assert.equal(result.state, 'unavailable'); assert.equal(result.value, null);
  }
});

test('geo and DNS caches have separate TTLs; failures retry without blocking the other lookup', async t => {
  let now = 1000, geoCalls = 0, dnsCalls = 0;
  const service = createEnrichmentService({ now: () => now,
    fetch: async () => { geoCalls++; return response(location()); },
    reverse: async () => { dnsCalls++; return ['DNS.GOOGLE.']; } });
  t.after(() => service.shutdown());
  await settle(() => service.geo('8.8.8.8'));
  assert.equal((await settle(() => service.domain('8.8.8.8'))).value, 'dns.google');
  now += 60 * 60_000;
  service.geo('8.8.8.8'); await settle(() => service.domain('8.8.8.8'));
  assert.equal(geoCalls, 1); assert.equal(dnsCalls, 2);
  now += 24 * 60 * 60_000; await settle(() => service.geo('8.8.8.8')); assert.equal(geoCalls, 2);
});

test('geo 429 pauses all geo requests while DNS continues; retry-after is respected', async t => {
  let now = 1000, calls = 0;
  const service = createEnrichmentService({ now: () => now,
    fetch: async () => { calls++; return calls === 1 ? response({}, 429, { 'Retry-After': '120' }) : response(location()); },
    reverse: async () => ['dns.google'] });
  t.after(() => service.shutdown());
  const limited = await settle(() => service.geo('8.8.8.8'));
  assert.equal(limited.state, 'rate-limited'); assert.equal(limited.retryAt, now + 120_000);
  assert.equal((await settle(() => service.geo('1.1.1.1'))).state, 'rate-limited'); assert.equal(calls, 1);
  assert.equal((await settle(() => service.domain('8.8.8.8'))).value, 'dns.google');
  now += 120_001; assert.equal((await settle(() => service.geo('8.8.8.8'))).state, 'ready'); assert.equal(calls, 2);
});

test('PTR names are validated and missing records get negative caching', async t => {
  let now = 1000, calls = 0;
  const service = createEnrichmentService({ ...offline, now: () => now, reverse: async ip => {
    calls++;
    if (ip === '1.1.1.1') throw Object.assign(new Error(), { code: 'ENOTFOUND' });
    return ['<script>alert(1)</script>', '-bad.example', 'valid.example.'];
  } });
  t.after(() => service.shutdown());
  assert.equal((await settle(() => service.domain('8.8.8.8'))).value, 'valid.example');
  assert.equal((await settle(() => service.domain('1.1.1.1'))).value, null);
  service.domain('1.1.1.1'); assert.equal(calls, 2);
  now += 5 * 60_000; await settle(() => service.domain('1.1.1.1')); assert.equal(calls, 3);
});

test('geo concurrency and queue are bounded; shutdown aborts requests without starting queued work', async t => {
  let calls = 0, cancelled = 0;
  const service = createEnrichmentService({ ...offline, fetch: async (_url, options) => {
    calls++;
    return new Promise<Response>((_resolve, reject) => options?.signal?.addEventListener('abort', () => { cancelled++; reject(new Error('Aborted')); }, { once: true }));
  } });
  t.after(() => service.shutdown());
  for (let i = 1; i < 200; i++) assert.equal(service.geo('8.8.4.' + i).state, 'pending');
  assert.equal(calls, 2);
  service.shutdown(); await setImmediate();
  assert.equal(calls, 2); assert.equal(cancelled, 2);
});

test('network deadline aborts stalled requests and releases a queue slot', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let cancelled = 0;
  const service = createEnrichmentService({ ...offline, fetch: async (_url, options) =>
    new Promise<Response>((_resolve, reject) => options?.signal?.addEventListener('abort', () => { cancelled++; reject(new Error('Timeout')); }, { once: true })) });
  t.after(() => service.shutdown());
  service.geo('8.8.8.8'); t.mock.timers.tick(4000); await setImmediate();
  assert.equal(service.geo('8.8.8.8').state, 'unavailable'); assert.equal(cancelled, 1);
});

test('host public-IP change drops the previous location until the new geo lookup completes', async t => {
  let ip = '8.8.8.8', now = 1000;
  const service = createEnrichmentService({ ...offline, now: () => now, fetch: async url => {
    const parsed = new URL(String(url));
    return parsed.hostname === 'api64.ipify.org' ? response({ ip }) : response(location(decodeURIComponent(parsed.pathname.slice(1))));
  } });
  t.after(() => service.shutdown());
  const first = await service.host(); assert.equal(first.publicIPStatus, 'ready'); assert.equal(first.geoStatus, 'pending');
  await settle(() => service.geo(ip));
  assert.equal((await service.host()).geoStatus, 'ready');
  ip = '1.1.1.1'; now += 31_000;
  const changed = await service.host(true);
  assert.equal(changed.publicIP, ip); assert.equal(changed.geo, null); assert.equal(changed.geoStatus, 'pending');
});
