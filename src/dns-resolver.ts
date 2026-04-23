import { reverse } from 'node:dns/promises';

const cache = new Map<string, { domain: string; timestamp: number; ttl: number }>();
const CACHE_TTL_SUCCESS = 30 * 60 * 1000; // 30 minutes for successful lookups
const CACHE_TTL_FAILURE = 60 * 1000; // 1 minute for failures (avoid pinning a transient miss)
const pendingLookups = new Map<string, Promise<{ domain: string; ok: boolean }>>();

async function doReverse(ip: string): Promise<{ domain: string; ok: boolean }> {
  try {
    const hostnames = await reverse(ip);
    const domain = hostnames[0];
    if (domain) return { domain, ok: true };
    return { domain: '-', ok: false };
  } catch {
    return { domain: '-', ok: false };
  }
}

export async function reverseLookup(ip: string): Promise<string> {
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.timestamp < cached.ttl) {
    return cached.domain;
  }

  // Deduplicate concurrent lookups for the same IP
  let pending = pendingLookups.get(ip);
  if (!pending) {
    pending = doReverse(ip);
    pendingLookups.set(ip, pending);
  }

  try {
    const { domain, ok } = await pending;
    cache.set(ip, {
      domain,
      timestamp: Date.now(),
      ttl: ok ? CACHE_TTL_SUCCESS : CACHE_TTL_FAILURE,
    });
    return domain;
  } finally {
    pendingLookups.delete(ip);
  }
}

export async function reverseLookupBatch(ips: string[]): Promise<Map<string, string>> {
  const results = new Map<string, string>();
  const unique = [...new Set(ips)];

  // `reverseLookup` never throws — it returns '-' on failure — so this is
  // effectively Promise.all, but `allSettled` keeps us robust if that ever
  // changes. No post-fill pass needed.
  await Promise.allSettled(
    unique.map(async (ip) => {
      results.set(ip, await reverseLookup(ip));
    })
  );

  return results;
}
