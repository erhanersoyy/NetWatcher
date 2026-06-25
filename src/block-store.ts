import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BlockRecord, BlockEvent, BlockHistoryResponse } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// src/ (dev via tsx) or dist/ (built) → ../data at project root. Overridable
// via NETWATCHER_DATA_DIR so tests can isolate to a temp dir. Read lazily
// (per call) so a test setting the env var after import still takes effect.
function dataDir(): string {
  return process.env.NETWATCHER_DATA_DIR || join(__dirname, '..', 'data');
}
function storePath(): string {
  return join(dataDir(), 'blocks.json');
}

interface StoreShape {
  active: Record<string, BlockRecord>;
  history: BlockEvent[];
}

function emptyStore(): StoreShape {
  return { active: {}, history: [] };
}

async function readStore(): Promise<StoreShape> {
  try {
    const raw = await readFile(storePath(), 'utf8');
    const data = JSON.parse(raw) as Partial<StoreShape>;
    return {
      active: data.active ?? {},
      history: Array.isArray(data.history) ? data.history : [],
    };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return emptyStore();
    throw err;
  }
}

async function writeStore(data: StoreShape): Promise<void> {
  const path = storePath();
  await mkdir(dirname(path), { recursive: true });
  const tmp = path + '.tmp';
  await writeFile(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  await rename(tmp, path);
}

// Serialize writes so two concurrent block requests don't race on read/write.
let writeChain: Promise<unknown> = Promise.resolve();
function serialize<T>(op: () => Promise<T>): Promise<T> {
  const next = writeChain.then(op, op);
  writeChain = next.catch(() => undefined);
  return next;
}

export function recordBlock(
  ip: string,
  meta: { country: string | null; countryCode?: string | null; isp?: string | null },
  appliedBoot: number | null = null,
): Promise<void> {
  return serialize(async () => {
    const store = await readStore();
    const at = Date.now();
    const country = meta.country ?? null;
    const countryCode = meta.countryCode ?? null;
    const isp = meta.isp ?? null;
    store.active[ip] = { ip, country, countryCode, isp, blockedAt: at, appliedBoot };
    store.history.push({ ip, action: 'block', at, country, countryCode, isp });
    await writeStore(store);
  });
}

export function recordUnblock(ip: string): Promise<void> {
  return serialize(async () => {
    const store = await readStore();
    const prev = store.active[ip];
    delete store.active[ip];
    store.history.push({
      ip,
      action: 'unblock',
      at: Date.now(),
      country: prev?.country ?? null,
      countryCode: prev?.countryCode ?? null,
      isp: prev?.isp ?? null,
    });
    await writeStore(store);
  });
}

// Re-stamp the boot id on the currently-active records for the given IPs —
// called after a successful re-apply so they no longer count as stale.
// Leaves records not in `ips` (and any IP no longer active) untouched.
export function markReapplied(ips: string[], bootId: number): Promise<void> {
  return serialize(async () => {
    const store = await readStore();
    let changed = false;
    for (const ip of ips) {
      const rec = store.active[ip];
      if (rec) { rec.appliedBoot = bootId; changed = true; }
    }
    if (changed) await writeStore(store);
  });
}

// Pure: how many active blocks were last applied in a different boot than the
// current one (or never marked) — i.e. almost certainly not enforced anymore.
export function countStaleBlocks(active: BlockRecord[], currentBoot: number): number {
  return active.filter((r) => r.appliedBoot !== currentBoot).length;
}

// Drop one session's worth of events for an IP — the `block` event at
// `blockedAt` and, when the session actually ended in an unblock, the
// paired `unblock` event at `unblockedAt`. Leaves any other sessions
// (historical or future) for the same IP untouched.
//
// Refuses when the `block` being removed is the currently active one —
// removing it would leave the live pfctl rule without a matching record.
// Superseded rows pass `unblockedAt = null` because their "end time" is
// a different block's timestamp, not a real unblock event to delete.
export function deleteBlockHistoryRow(
  ip: string,
  blockedAt: number,
  unblockedAt: number | null,
): Promise<{ success: boolean; removed: number; message?: string }> {
  return serialize(async () => {
    const store = await readStore();
    const active = store.active[ip];
    if (active && active.blockedAt === blockedAt) {
      return { success: false, removed: 0, message: 'Block is still active — unblock it first.' };
    }
    const before = store.history.length;
    store.history = store.history.filter((e) => {
      if (e.ip !== ip) return true;
      if (e.action === 'block' && e.at === blockedAt) return false;
      if (unblockedAt !== null && e.action === 'unblock' && e.at === unblockedAt) return false;
      return true;
    });
    const removed = before - store.history.length;
    if (removed > 0) await writeStore(store);
    return { success: true, removed };
  });
}

export async function getBlockHistory(): Promise<BlockHistoryResponse> {
  const store = await readStore();
  return {
    active: Object.values(store.active).sort((a, b) => b.blockedAt - a.blockedAt),
    history: [...store.history].sort((a, b) => b.at - a.at),
  };
}
