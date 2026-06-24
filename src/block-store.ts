import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BlockRecord, BlockEvent, BlockHistoryResponse } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// src/ (dev via tsx) or dist/ (built) → ../data/blocks.json at project root.
const DATA_DIR = join(__dirname, '..', 'data');
const STORE_PATH = join(DATA_DIR, 'blocks.json');

interface StoreShape {
  active: Record<string, BlockRecord>;
  history: BlockEvent[];
}

function emptyStore(): StoreShape {
  return { active: {}, history: [] };
}

async function readStore(): Promise<StoreShape> {
  try {
    const raw = await readFile(STORE_PATH, 'utf8');
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
  await mkdir(DATA_DIR, { recursive: true });
  const tmp = STORE_PATH + '.tmp';
  await writeFile(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  await rename(tmp, STORE_PATH);
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
): Promise<void> {
  return serialize(async () => {
    const store = await readStore();
    const at = Date.now();
    const country = meta.country ?? null;
    const countryCode = meta.countryCode ?? null;
    const isp = meta.isp ?? null;
    store.active[ip] = { ip, country, countryCode, isp, blockedAt: at };
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

// Bring the persisted `active` map in line with a fresh pfctl snapshot.
// Any IP we think is active but pfctl doesn't have is treated as an
// implicit unblock (reboot, external `pfctl -F all`, anchor never
// re-loaded, etc.) — we append an unblock event so the history timeline
// stays coherent rather than claiming a block that isn't actually in
// effect. No-op when nothing drifted. Callers must only invoke this
// with an AUTHORITATIVE snapshot (never null/unknown).
export function reconcileActive(livePfctlIPs: string[]): Promise<{ removed: string[] }> {
  return serialize(async () => {
    const live = new Set(livePfctlIPs);
    const store = await readStore();
    const orphans = Object.keys(store.active).filter((ip) => !live.has(ip));
    if (orphans.length === 0) return { removed: [] };
    const at = Date.now();
    for (const ip of orphans) {
      const prev = store.active[ip];
      delete store.active[ip];
      store.history.push({
        ip,
        action: 'unblock',
        at,
        country: prev?.country ?? null,
        countryCode: prev?.countryCode ?? null,
        isp: prev?.isp ?? null,
      });
    }
    await writeStore(store);
    return { removed: orphans };
  });
}

export async function getBlockHistory(): Promise<BlockHistoryResponse> {
  const store = await readStore();
  return {
    active: Object.values(store.active).sort((a, b) => b.blockedAt - a.blockedAt),
    history: [...store.history].sort((a, b) => b.at - a.at),
  };
}
