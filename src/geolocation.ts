import { BlockList, isIP } from 'node:net';
import { Resolver } from 'node:dns/promises';
import type { GeoInfo } from './types.js';

export type LookupState = 'pending' | 'ready' | 'unavailable' | 'rate-limited';
interface Lookup<T> { value: T | null; state: LookupState; retryAt?: number }
interface CacheEntry<T> { result: Lookup<T>; expiresAt: number }
const DAY = 24 * 60 * 60_000;
const privateRanges = new BlockList();
for (const [ip, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16]] as const) privateRanges.addSubnet(ip, prefix, 'ipv4');
for (const [ip, prefix] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10]] as const) privateRanges.addSubnet(ip, prefix, 'ipv6');
const reservedRanges = new BlockList();
for (const [ip, prefix] of [['192.0.0.0', 24], ['192.0.2.0', 24], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]] as const) reservedRanges.addSubnet(ip, prefix, 'ipv4');
reservedRanges.addSubnet('2001:db8::', 32, 'ipv6');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');

export function normalizeIP(ip: string): string | null {
  if (typeof ip !== 'string' || ip.includes('%') || !isIP(ip)) return null;
  if (isIP(ip) === 4) return ip;
  const normalized = new URL('http://[' + ip + ']/').hostname.slice(1, -1);
  const mapped = normalized.match(/^::ffff:([\da-f]+):([\da-f]+)$/);
  if (!mapped) return normalized;
  const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join('.');
}

export function isPrivateIP(ip: string): boolean {
  const normalized = normalizeIP(ip);
  return normalized !== null && privateRanges.check(normalized, isIP(normalized) === 6 ? 'ipv6' : 'ipv4');
}

export function isPublicIP(ip: string): boolean {
  const normalized = normalizeIP(ip);
  if (!normalized || isPrivateIP(normalized)) return false;
  const family = isIP(normalized) === 6 ? 'ipv6' : 'ipv4';
  return !reservedRanges.check(normalized, family) && (family === 'ipv4' || globalV6.check(normalized, 'ipv6'));
}

class RateLimited extends Error {
  constructor(readonly retryAt: number) { super('Provider rate limit'); }
}

function retryTime(value: string | null, now: number): number {
  const delay = value && /^\d+$/.test(value) ? Number(value) * 1000 : value ? Date.parse(value) - now : DAY;
  return now + Math.max(60_000, Math.min(DAY, Number.isFinite(delay) ? delay : DAY));
}

/** Bounded, deduplicated background lookups. Polls read a snapshot, never wait
 * for remote services. Geo and DNS have separate queues and failure states. */
function lookupQueue<T>(lookup: (ip: string) => Promise<T | null>, ttl: number, concurrency: number, now: () => number) {
  const cache = new Map<string, CacheEntry<T>>();
  const queue: { ip: string; entry: CacheEntry<T> }[] = [];
  let running = 0, stopped = false;
  function pump(): void {
    while (!stopped && running < concurrency && queue.length) {
      const { ip, entry } = queue.shift()!;
      running++;
      void (async () => {
        try {
          const value = await lookup(ip);
          entry.result = { value, state: value === null ? 'unavailable' : 'ready' };
          entry.expiresAt = now() + (value === null ? 5 * 60_000 : ttl);
        } catch (error) {
          const retryAt = error instanceof RateLimited ? error.retryAt : now() + 60_000;
          entry.result = { value: null, state: error instanceof RateLimited ? 'rate-limited' : 'unavailable', retryAt };
          entry.expiresAt = retryAt;
        } finally { running--; pump(); }
      })();
    }
  }
  return {
    get(ip: string, priority = false): Lookup<T> {
      if (stopped) return { value: null, state: 'unavailable' };
      const cached = cache.get(ip);
      if (cached && (cached.result.state === 'pending' || cached.expiresAt > now())) {
        cache.delete(ip); cache.set(ip, cached);
        return cached.result;
      }
      if (queue.length >= 128) return { value: null, state: 'pending' };
      if (!cached && cache.size >= 2048) {
        const oldest = [...cache].find(([, e]) => e.result.state !== 'pending');
        if (!oldest) return { value: null, state: 'pending' };
        cache.delete(oldest[0]);
      }
      const entry: CacheEntry<T> = { result: { value: null, state: 'pending' }, expiresAt: 0 };
      cache.set(ip, entry);
      if (priority) queue.unshift({ ip, entry }); else queue.push({ ip, entry });
      pump();
      return entry.result;
    },
    stop() { stopped = true; queue.length = 0; cache.clear(); },
  };
}

interface Dependencies {
  fetch: typeof fetch;
  reverse: (ip: string, signal: AbortSignal) => Promise<string[]>;
  now: () => number;
}

const defaults: Dependencies = {
  fetch: (...args) => fetch(...args), now: Date.now,
  async reverse(ip, signal) {
    const resolver = new Resolver({ timeout: 2000, tries: 1 });
    const cancel = () => resolver.cancel();
    signal.throwIfAborted();
    signal.addEventListener('abort', cancel, { once: true });
    try { return await resolver.reverse(ip); }
    finally { signal.removeEventListener('abort', cancel); }
  },
};

function text(value: unknown, max = 200): string {
  return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max) : '';
}

export function createEnrichmentService(overrides: Partial<Dependencies> = {}) {
  const deps = { ...defaults, ...overrides };
  const active = new Set<AbortController>();
  let stopped = false, geoRetryAt = 0;
  async function bounded<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (stopped) throw new Error('Stopped');
    const controller = new AbortController(); active.add(controller);
    const timer = setTimeout(() => controller.abort(), 4000);
    try { return await work(controller.signal); }
    finally { clearTimeout(timer); active.delete(controller); }
  }
  async function json(url: string): Promise<Record<string, unknown>> {
    return bounded(async signal => {
      const response = await deps.fetch(url, { signal, redirect: 'error', headers: { Accept: 'application/json' } });
      if (!response.ok) {
        await response.body?.cancel();
        if (response.status === 429) throw new RateLimited(retryTime(response.headers.get('retry-after'), deps.now()));
        throw new Error('Lookup unavailable');
      }
      const reader = response.body?.getReader();
      if (!reader) throw new Error('Empty response');
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 16 * 1024) throw new Error('Response too large');
          chunks.push(value);
        }
      } finally { await reader.cancel(); }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid response');
      return value;
    });
  }

  // 1. Public IP: coalesced HTTPS, cached five minutes; failures retry later.
  let publicCache: { value: string | null; expiresAt: number; checkedAt: number } | null = null;
  let publicRequest: Promise<string | null> | null = null;
  async function publicIP(fresh = false): Promise<string | null> {
    if (stopped) return null;
    if (publicRequest) return publicRequest;
    if (publicCache && publicCache.expiresAt > deps.now() && (!publicCache.value || !fresh || deps.now() - publicCache.checkedAt < 30_000)) return publicCache.value;
    publicRequest = (async () => {
      let value: string | null = null, expiresAt = deps.now() + 60_000;
      try {
        const data = await json('https://api64.ipify.org?format=json');
        const ip = normalizeIP(data.ip as string);
        if (!ip || !isPublicIP(ip)) throw new Error('Invalid public IP');
        value = ip; expiresAt = deps.now() + 5 * 60_000;
      } catch (error) { if (error instanceof RateLimited) expiresAt = error.retryAt; }
      publicCache = { value, expiresAt, checkedAt: deps.now() };
      return value;
    })().finally(() => { publicRequest = null; });
    return publicRequest;
  }

  // 2. Geography over HTTPS; local/reserved addresses never leave the host.
  const geoQueue = lookupQueue<GeoInfo>(async ip => {
    if (geoRetryAt > deps.now()) throw new RateLimited(geoRetryAt);
    let data: Record<string, unknown>;
    try {
      data = await json('https://ipwho.is/' + encodeURIComponent(ip) + '?fields=ip,success,country,country_code,city,latitude,longitude,connection.isp,message');
    } catch (error) {
      if (error instanceof RateLimited) geoRetryAt = Math.max(geoRetryAt, error.retryAt);
      throw error;
    }
    if (data.success !== true) return null;
    const lat = data.latitude, lon = data.longitude;
    if (normalizeIP(data.ip as string) !== ip || typeof lat !== 'number' || typeof lon !== 'number'
      || !Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180
      || !/^[A-Z]{2}$/.test(text(data.country_code)) || !text(data.country)) throw new Error('Invalid geography');
    return { country: text(data.country), countryCode: text(data.country_code, 2), city: text(data.city),
      isp: text((data.connection as { isp?: unknown } | null)?.isp), lat, lon };
  }, DAY, 2, deps.now);

  function geo(ip: string, priority = false): Lookup<GeoInfo> {
    const normalized = normalizeIP(ip);
    if (!normalized) return { value: null, state: 'unavailable' };
    if (isPrivateIP(normalized)) return { state: 'ready', value: { country: 'Local', countryCode: 'LO', city: '', isp: 'Private Network', lat: 0, lon: 0 } };
    if (!isPublicIP(normalized)) return { value: null, state: 'unavailable' };
    return geoQueue.get(normalized, priority);
  }

  // 3. PTR records use Node's configured DNS servers and an independent queue.
  const dnsQueue = lookupQueue<string>(async ip => {
    try {
      const names = await bounded(signal => deps.reverse(ip, signal));
      return names.map(name => name.replace(/\.$/, '').toLowerCase())
        .find(name => name.length <= 253 && name.split('.').every(label => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/.test(label))) ?? null;
    } catch (error) {
      if (['ENOTFOUND', 'ENODATA'].includes((error as NodeJS.ErrnoException).code || '')) return null;
      throw error;
    }
  }, 60 * 60_000, 4, deps.now);

  function domain(ip: string): Lookup<string> {
    const normalized = normalizeIP(ip);
    return normalized && isPublicIP(normalized) ? dnsQueue.get(normalized) : { value: null, state: 'unavailable' };
  }

  return {
    publicIP, geo, domain,
    async host(fresh = false) {
      const ip = await publicIP(fresh);
      const location: Lookup<GeoInfo> = ip ? geo(ip, true) : { value: null, state: 'unavailable' };
      return { publicIP: ip || 'Unavailable', geo: location.value, publicIPStatus: ip ? 'ready' as const : 'unavailable' as const,
        geoStatus: location.state, geoRetryAt: location.retryAt, checkedAt: publicCache?.checkedAt ?? null };
    },
    shutdown() {
      stopped = true; geoQueue.stop(); dnsQueue.stop();
      for (const controller of active) controller.abort();
    },
  };
}

export const enrichment = createEnrichmentService();
