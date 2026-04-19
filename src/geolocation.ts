import type { GeoInfo } from './types.js';

interface CacheEntry {
  data: GeoInfo;
  timestamp: number;
}

const cache = new Map<string, CacheEntry>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
let lastBatchTime = 0;
const MIN_BATCH_INTERVAL = 1500; // ms between batch requests

function isPrivateIP(ip: string): boolean {
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('127.')) return true;
  if (ip === '::1' || ip === '::' || ip === '0.0.0.0' || ip === '*') return true;
  if (ip.startsWith('fe80:')) return true;
  if (ip.startsWith('169.254.')) return true;

  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — recurse on the embedded v4
  const mapped = ip.toLowerCase();
  if (mapped.startsWith('::ffff:')) {
    const v4 = mapped.slice(7);
    if (v4.includes('.')) return isPrivateIP(v4);
  }

  // 172.16.0.0 - 172.31.255.255
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }

  // 100.64.0.0/10 — CGNAT / shared address space (RFC 6598)
  if (ip.startsWith('100.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 64 && second <= 127) return true;
  }

  // IPv6 Unique Local Addresses fc00::/7  (fc..–fd..)
  if (/^f[cd][0-9a-f]{2}:/i.test(ip)) return true;

  return false;
}

export { isPrivateIP };

export async function lookupSingleIP(ip: string): Promise<GeoInfo | null> {
  if (isPrivateIP(ip)) return null;
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached.data;
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,lat,lon`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const d = await res.json() as { status: string; country?: string; countryCode?: string; city?: string; isp?: string; lat?: number; lon?: number };
    if (d.status !== 'success') return null;
    const geo: GeoInfo = {
      country: d.country ?? 'Unknown', countryCode: d.countryCode ?? '??',
      city: d.city ?? '', isp: d.isp ?? 'Unknown', lat: d.lat ?? 0, lon: d.lon ?? 0,
    };
    cache.set(ip, { data: geo, timestamp: Date.now() });
    return geo;
  } catch { return null; }
}

export async function lookupIPs(ips: string[]): Promise<Map<string, GeoInfo>> {
  const results = new Map<string, GeoInfo>();
  const now = Date.now();
  const uncached: string[] = [];

  for (const ip of ips) {
    if (isPrivateIP(ip)) {
      results.set(ip, { country: 'Local', countryCode: 'LO', city: '', isp: 'Private Network', lat: 0, lon: 0 });
      continue;
    }

    const entry = cache.get(ip);
    if (entry && now - entry.timestamp < CACHE_TTL) {
      results.set(ip, entry.data);
      continue;
    }

    uncached.push(ip);
  }

  if (uncached.length === 0) return results;

  // Batch lookup (ip-api.com supports up to 100 per request)
  const batches = [];
  for (let i = 0; i < uncached.length; i += 100) {
    batches.push(uncached.slice(i, i + 100));
  }

  for (const batch of batches) {
    // Rate limit: wait out the remaining interval rather than dropping the lookup
    const elapsed = Date.now() - lastBatchTime;
    if (elapsed < MIN_BATCH_INTERVAL) {
      await new Promise((r) => setTimeout(r, MIN_BATCH_INTERVAL - elapsed));
    }

    try {
      lastBatchTime = Date.now();
      const response = await fetch('http://ip-api.com/batch?fields=status,country,countryCode,city,isp,lat,lon,query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batch),
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) continue;

      const data = await response.json() as Array<{
        status: string;
        query: string;
        country?: string;
        countryCode?: string;
        city?: string;
        isp?: string;
        lat?: number;
        lon?: number;
      }>;

      for (const entry of data) {
        if (entry.status === 'success') {
          const geo: GeoInfo = {
            country: entry.country ?? 'Unknown',
            countryCode: entry.countryCode ?? '??',
            city: entry.city ?? '',
            isp: entry.isp ?? 'Unknown',
            lat: entry.lat ?? 0,
            lon: entry.lon ?? 0,
          };
          cache.set(entry.query, { data: geo, timestamp: Date.now() });
          results.set(entry.query, geo);
        }
      }
    } catch {
      // Network error or timeout — skip, will retry next poll
    }
  }

  return results;
}
