import { getTrafficSnapshot, type TrafficStats as SnapshotStats } from './traffic.js';

/** Per-connection byte counters derived from periodic nettop samples. */
export interface TrafficStats {
  bytesIn: number;
  bytesOut: number;
  updatedAt: number;
}

/** Wire shape: one entry per changed connection, flushed per sample. */
export interface TrafficDelta {
  key: string;
  bytesIn: number;
  bytesOut: number;
}

type Subscriber = (delta: TrafficDelta[]) => void;

const SAMPLE_INTERVAL_MS = 1000;
const STOP_GRACE_MS = 5000;
const SNAPSHOT_TIMEOUT_MS = 1500;

const latest = new Map<string, TrafficStats>();
const subscribers = new Set<Subscriber>();

let sampleTimer: NodeJS.Timeout | null = null;
let stopTimer: NodeJS.Timeout | null = null;
let sampleInFlight = false;

/**
 * Run one nettop snapshot, diff against what we have, and emit only the
 * keys whose bytes changed. We rely on `getTrafficSnapshot`'s proven
 * `nettop -L 1` path — the continuous-mode variant block-buffers its
 * stdout when piped (no output until 8KB fills up), which is why we
 * periodically invoke a one-shot instead of keeping a long-running child.
 */
async function tick(): Promise<void> {
  if (sampleInFlight || subscribers.size === 0) return;
  sampleInFlight = true;
  try {
    const snap: Map<string, SnapshotStats> = await getTrafficSnapshot(SNAPSHOT_TIMEOUT_MS);
    const now = Date.now();
    const delta: TrafficDelta[] = [];

    for (const [key, s] of snap) {
      const prev = latest.get(key);
      if (!prev || prev.bytesIn !== s.bytesIn || prev.bytesOut !== s.bytesOut) {
        latest.set(key, { bytesIn: s.bytesIn, bytesOut: s.bytesOut, updatedAt: now });
        delta.push({ key, bytesIn: s.bytesIn, bytesOut: s.bytesOut });
      }
    }

    // Drop stale connections that nettop no longer reports. Emitting a
    // delta for these would be misleading; the client's render path
    // naturally stops showing them when `/api/connections` prunes them.
    for (const key of latest.keys()) {
      if (!snap.has(key)) latest.delete(key);
    }

    if (delta.length === 0 || subscribers.size === 0) return;
    for (const sub of subscribers) {
      try {
        sub(delta);
      } catch (err) {
        console.error('[traffic-stream] subscriber threw:', err);
      }
    }
  } catch (err) {
    console.error('[traffic-stream] snapshot failed:', err);
  } finally {
    sampleInFlight = false;
  }
}

function startSampling(): void {
  if (sampleTimer) return;
  // Kick once immediately so the first subscriber doesn't wait a full
  // interval for its first delta.
  void tick();
  sampleTimer = setInterval(() => { void tick(); }, SAMPLE_INTERVAL_MS);
  console.log('[traffic-stream] sampling started');
}

function stopSampling(): void {
  if (!sampleTimer) return;
  clearInterval(sampleTimer);
  sampleTimer = null;
  console.log('[traffic-stream] sampling stopped');
}

/**
 * Subscribe to live traffic deltas. Returns an unsubscribe function.
 *
 * First subscriber starts the 1-second sampling interval; last
 * unsubscribe schedules a grace-period stop so that rapid reconnects
 * (page reload) don't churn the child process.
 *
 * On subscribe we push the full current snapshot asynchronously so a
 * fresh client sees values immediately instead of waiting one tick.
 */
export function subscribeTrafficStream(sub: Subscriber): () => void {
  subscribers.add(sub);
  if (stopTimer) {
    clearTimeout(stopTimer);
    stopTimer = null;
  }
  if (!sampleTimer) startSampling();

  queueMicrotask(() => {
    if (!subscribers.has(sub) || latest.size === 0) return;
    const snapshot: TrafficDelta[] = [];
    for (const [key, s] of latest) {
      snapshot.push({ key, bytesIn: s.bytesIn, bytesOut: s.bytesOut });
    }
    try {
      sub(snapshot);
    } catch (err) {
      console.error('[traffic-stream] initial snapshot threw:', err);
    }
  });

  return () => {
    if (!subscribers.delete(sub)) return;
    if (subscribers.size === 0 && sampleTimer && !stopTimer) {
      stopTimer = setTimeout(() => {
        stopTimer = null;
        if (subscribers.size === 0) stopSampling();
      }, STOP_GRACE_MS);
    }
  };
}

/** Snapshot accessor (used by `/api/connections` for merging). */
export function getLatestTrafficStats(): Map<string, TrafficStats> {
  return latest;
}

/**
 * Shutdown hook — called from the SIGINT/SIGTERM handler in `index.ts`.
 * Clears the sample timer and the grace-period stop timer so no new
 * `nettop` child gets spawned mid-shutdown; any snapshot already in
 * flight completes under its own 1.5s timeout.
 */
export function shutdownTrafficStream(): void {
  if (sampleTimer) {
    clearInterval(sampleTimer);
    sampleTimer = null;
  }
  if (stopTimer) {
    clearTimeout(stopTimer);
    stopTimer = null;
  }
  subscribers.clear();
}
