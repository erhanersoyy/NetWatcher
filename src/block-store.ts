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

export function recordBlock(ip: string, country: string | null): Promise<void> {
  return serialize(async () => {
    const store = await readStore();
    const at = Date.now();
    store.active[ip] = { ip, country, blockedAt: at };
    store.history.push({ ip, action: 'block', at, country });
    await writeStore(store);
  });
}

export function recordUnblock(ip: string): Promise<void> {
  return serialize(async () => {
    const store = await readStore();
    const prev = store.active[ip];
    delete store.active[ip];
    store.history.push({ ip, action: 'unblock', at: Date.now(), country: prev?.country ?? null });
    await writeStore(store);
  });
}

export async function getBlockHistory(): Promise<BlockHistoryResponse> {
  const store = await readStore();
  return {
    active: Object.values(store.active).sort((a, b) => b.blockedAt - a.blockedAt),
    history: [...store.history].sort((a, b) => b.at - a.at),
  };
}
