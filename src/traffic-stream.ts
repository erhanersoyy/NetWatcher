import { spawn, type ChildProcess } from 'node:child_process';
import { getTrafficSnapshot, parseConnectionLine, type TrafficStats as SnapshotStats } from './traffic.js';

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

// Continuous-mode tunables
const CONTINUOUS_IDLE_FLUSH_MS = 250;  // quiet period that marks end-of-sample
const CONTINUOUS_STARTUP_MS = 5000;    // if no data in this window, declare dead
const CONTINUOUS_WATCHDOG_MS = 10000;  // after startup, this long without data = dead
const ANSI_RE = /\x1b\[[0-9;?]*[a-zA-Z]/g;

const latest = new Map<string, TrafficStats>();
const subscribers = new Set<Subscriber>();

// One-shot fallback sampler state
let sampleTimer: NodeJS.Timeout | null = null;
let stopTimer: NodeJS.Timeout | null = null;
let sampleInFlight = false;

// Continuous sampler state (nettop running inside a PTY via script(1))
let continuousChild: ChildProcess | null = null;
let continuousBuffer = '';
let pendingSample = new Map<string, SnapshotStats>();
let continuousFlushTimer: NodeJS.Timeout | null = null;
let continuousLastDataAt = 0;
let continuousStartedAt = 0;
let continuousWatchdog: NodeJS.Timeout | null = null;
// Once continuous mode fails in this process, don't retry — we fall back
// permanently to the one-shot path so a misbehaving environment
// (missing `script`, nettop build without `-L 0`, SIP weirdness) doesn't
// thrash child processes.
let continuousDisabled = process.env.NW_TRAFFIC_CONTINUOUS === '0';

/**
 * One-shot sampler tick — spawns `nettop -L 1`, diffs, emits. Used as the
 * fallback when continuous mode is disabled or failed, and as the historical
 * default before the long-running child was introduced.
 */
async function tickOneShot(): Promise<void> {
  if (sampleInFlight || subscribers.size === 0) return;
  sampleInFlight = true;
  try {
    const snap = await getTrafficSnapshot(SNAPSHOT_TIMEOUT_MS);
    flushSample(snap);
  } catch (err) {
    console.error('[traffic-stream] one-shot snapshot failed:', err);
  } finally {
    sampleInFlight = false;
  }
}

/**
 * Merge a completed sample into `latest`, emit deltas for changed keys,
 * and prune keys that vanished since the previous sample. Shared by both
 * the continuous sampler and the one-shot fallback.
 */
function flushSample(snap: Map<string, SnapshotStats>): void {
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
}

/**
 * Spawn `nettop` wrapped in a PTY so its stdout is line-buffered instead
 * of block-buffered (8KB fill) when read via a pipe. macOS ships `script(1)`
 * which provides a zero-dep PTY wrapper: `script -q /dev/null <cmd>`.
 *
 * nettop is run in log mode (`-L 0` = unlimited samples) with `-s 1` for
 * a 1-second sample cadence. Each sample's lines arrive in a burst; we
 * accumulate into `pendingSample` and flush on a ~250 ms quiet period,
 * which cleanly separates samples without needing a delimiter.
 *
 * Returns true if the child spawned (doesn't guarantee it produces data —
 * the watchdog handles that). Returns false if `script` is unavailable
 * or the exec failed synchronously.
 */
function startContinuousSampler(): boolean {
  if (continuousDisabled) return false;
  if (continuousChild) return true;

  let child: ChildProcess;
  try {
    child = spawn(
      'script',
      ['-q', '/dev/null', 'nettop', '-L', '0', '-s', '1', '-nx', '-J', 'bytes_in,bytes_out'],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
  } catch (err) {
    console.warn('[traffic-stream] failed to spawn continuous sampler:', (err as Error).message);
    continuousDisabled = true;
    return false;
  }

  continuousChild = child;
  continuousBuffer = '';
  pendingSample = new Map();
  continuousLastDataAt = 0;
  continuousStartedAt = Date.now();

  child.on('error', (err) => {
    console.warn('[traffic-stream] continuous sampler error:', err.message);
    failContinuousSampler();
  });
  child.on('exit', (code, signal) => {
    // Only fail if it exited unexpectedly — shutdown path kills it deliberately.
    if (continuousChild === child) {
      console.warn(`[traffic-stream] continuous sampler exited (code=${code}, signal=${signal})`);
      failContinuousSampler();
    }
  });

  child.stdout!.on('data', (chunk: Buffer) => {
    continuousLastDataAt = Date.now();
    // ANSI escape sequences can leak through the PTY even in log mode
    // (e.g. color reset on some terminal types). Strip before parsing.
    continuousBuffer += chunk.toString('utf8').replace(ANSI_RE, '');

    const lastNewline = continuousBuffer.lastIndexOf('\n');
    if (lastNewline === -1) return;
    const complete = continuousBuffer.slice(0, lastNewline);
    continuousBuffer = continuousBuffer.slice(lastNewline + 1);

    for (const raw of complete.split('\n')) {
      const line = raw.trim();
      if (!line) continue;
      if (!/^(tcp4|tcp6|udp4|udp6) /i.test(line)) continue;
      const parsed = parseConnectionLine(line);
      if (!parsed) continue;
      // Within one sample, nettop may report the same 5-tuple across
      // multiple PIDs — sum them. Cross-sample replacement happens in
      // flushSample() via the diff against `latest`.
      const existing = pendingSample.get(parsed.key);
      if (existing) {
        existing.bytesIn += parsed.bytesIn;
        existing.bytesOut += parsed.bytesOut;
      } else {
        pendingSample.set(parsed.key, { bytesIn: parsed.bytesIn, bytesOut: parsed.bytesOut });
      }
    }

    // Reset idle-flush timer: whenever nettop goes quiet for CONTINUOUS_IDLE_FLUSH_MS
    // we treat the accumulated pendingSample as one complete sample.
    if (continuousFlushTimer) clearTimeout(continuousFlushTimer);
    continuousFlushTimer = setTimeout(() => {
      continuousFlushTimer = null;
      if (pendingSample.size === 0) return;
      const sample = pendingSample;
      pendingSample = new Map();
      flushSample(sample);
    }, CONTINUOUS_IDLE_FLUSH_MS);
  });

  // Watchdog: if nettop never produces data (spawn succeeded but no output)
  // or stalls mid-session, fall back to one-shot for the rest of the process
  // lifetime. Cleared and replaced by `stopContinuousSampler()`.
  continuousWatchdog = setInterval(() => {
    if (!continuousChild) return;
    const now = Date.now();
    const window = continuousLastDataAt === 0
      ? now - continuousStartedAt
      : now - continuousLastDataAt;
    const limit = continuousLastDataAt === 0 ? CONTINUOUS_STARTUP_MS : CONTINUOUS_WATCHDOG_MS;
    if (window > limit) {
      console.warn(`[traffic-stream] continuous sampler idle for ${window}ms; falling back to one-shot`);
      failContinuousSampler();
    }
  }, 1000);

  console.log('[traffic-stream] continuous sampler started (nettop via PTY)');
  return true;
}

function stopContinuousSampler(): void {
  if (continuousFlushTimer) {
    clearTimeout(continuousFlushTimer);
    continuousFlushTimer = null;
  }
  if (continuousWatchdog) {
    clearInterval(continuousWatchdog);
    continuousWatchdog = null;
  }
  if (continuousChild) {
    const child = continuousChild;
    continuousChild = null;
    try { child.kill('SIGKILL'); } catch { /* already dead */ }
  }
  continuousBuffer = '';
  pendingSample = new Map();
}

/** Permanently disable continuous mode for the rest of the process and
 *  spin up the one-shot fallback if subscribers are still connected. */
function failContinuousSampler(): void {
  continuousDisabled = true;
  stopContinuousSampler();
  if (subscribers.size > 0 && !sampleTimer) {
    startOneShotSampler();
  }
}

function startOneShotSampler(): void {
  if (sampleTimer) return;
  void tickOneShot();
  sampleTimer = setInterval(() => { void tickOneShot(); }, SAMPLE_INTERVAL_MS);
  console.log('[traffic-stream] one-shot sampling started');
}

function stopOneShotSampler(): void {
  if (!sampleTimer) return;
  clearInterval(sampleTimer);
  sampleTimer = null;
}

function startSampling(): void {
  // Prefer continuous (long-running nettop inside a PTY). Fall back to
  // per-second one-shot only if continuous can't be started in this env.
  if (startContinuousSampler()) return;
  startOneShotSampler();
}

function stopSampling(): void {
  stopOneShotSampler();
  stopContinuousSampler();
  console.log('[traffic-stream] sampling stopped');
}

/**
 * Subscribe to live traffic deltas. Returns an unsubscribe function.
 *
 * First subscriber starts the sampler; last unsubscribe schedules a
 * grace-period stop so that rapid reconnects (page reload) don't churn
 * the child process.
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
  if (!sampleTimer && !continuousChild) startSampling();

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
    if (subscribers.size === 0 && (sampleTimer || continuousChild) && !stopTimer) {
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
 * flight completes under its own 1.5s timeout. Also kills the long-
 * running continuous sampler so no orphan `nettop`/`script` remains.
 */
export function shutdownTrafficStream(): void {
  stopOneShotSampler();
  stopContinuousSampler();
  if (stopTimer) {
    clearTimeout(stopTimer);
    stopTimer = null;
  }
  subscribers.clear();
}
