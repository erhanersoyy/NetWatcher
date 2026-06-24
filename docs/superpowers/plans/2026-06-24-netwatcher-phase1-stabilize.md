# NetWatcher Phase 1 — Stabilize & Accessibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the 8 verified bugs and the highest-impact accessibility gaps in NetWatcher without any architectural churn (no `app.js` split — that is Phase 2).

**Architecture:** Surgical, low-risk edits to existing files. Backend logic bugs get extracted into small pure helpers and covered by Node's built-in test runner (`node --test`, zero new dependencies). Frontend bugs (in the not-yet-modular `app.js`) get inline fixes plus a written manual-verification checklist; they receive real unit tests in Phase 2 once `app.js` is split into ES modules. Accessibility work is mostly CSS custom-property and HTML-attribute changes.

**Tech Stack:** Node.js ≥20, TypeScript (strict, no `any`), Express 5, vanilla JS/CSS frontend (no bundler), `tsx` for dev/test, pnpm 9.15.4.

## Global Constraints

- **Prefer the 50-line solution.** No frontend framework, bundler, or signals library. No new runtime dependencies. (User rule: minimal code.)
- **No `any`** in `src/` — use `unknown` + narrowing. Type external `fetch().json()` boundaries.
- **ES modules** (`import`/`export`), `.js` extensions in relative imports (NodeNext resolution).
- **macOS only**; frontend served as static files with **no build step** — `public/app.js` stays a single classic `<script>` in Phase 1.
- **Run `pnpm typecheck` after every backend edit.** It does not cover `public/`.
- **Conventional commits** (`fix:`, `a11y:`/`feat:`, `chore:`, `docs:`, `test:`). Commit after each task.
- Project docs/comments in **English**.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `package.json` | Modify | add `test` script |
| `src/proc-io.ts` | **Create** | tiny shared helper: `safeEndStdin(child, data)` (no-op error handler + end) |
| `src/proc-io.test.ts` | **Create** | regression test: ending a destroyed stdin does not throw |
| `src/firewall.ts` | Modify | use `safeEndStdin` in both `spawn` callsites |
| `src/net-iface.ts` | **Create** | pure `pickPrimaryIPv4(nets)` host-IP selector |
| `src/net-iface.test.ts` | **Create** | unit tests for interface selection |
| `src/routes.ts` | Modify | use `pickPrimaryIPv4` |
| `src/geolocation.ts` | Modify | serialize batch lookups; route `lookupSingleIP` through the limiter |
| `src/geolocation.test.ts` | **Create** | test that serialized ops never overlap |
| `src/system-health.ts` | Modify | delete dead `tempC`/`TEMP_C` |
| `src/types.ts` | Modify | add shared `ActionResult` interface |
| `public/app.js` | Modify | byte-truncation, liveTraffic prune, stale baseline, stream-health status, idle decay, keyboard rows, control labels, modal focus-trap |
| `public/index.html` | Modify | `aria-label`s, `role="status"`/`aria-live`, canvas label |
| `public/style.css` | Modify | global `:focus-visible`, `prefers-reduced-motion`, lift contrast tokens |
| `CLAUDE.md` | Modify | remove stale `globe.gl`/Three.js references |

**Out of scope (Phase 1b candidates, deliberately deferred):** usability quick wins from the audit — flash-new-rows, toast stacking, in-flight button disabling, kill confirm/undo, inline error+Retry in `#queue`, "(N hidden)" filter chips + Clear-filters. Listed here so they are not lost.

---

### Task 1: Fix `firewall.ts` stdin crash + add the test harness

A wrong sudo password or the 5 s timeout `SIGKILL`s the child; the subsequent `child.stdin.end(...)` then emits an `'error'` (EPIPE / `ERR_STREAM_DESTROYED`) on the **stdin stream**. The only handler is `child.on('error', …)` (the *ChildProcess* event, not the stream's), so the stdin error is unhandled and **crashes the whole Node process**. Fix once via a shared helper and reuse at both callsites.

**Files:**
- Create: `src/proc-io.ts`
- Create: `src/proc-io.test.ts`
- Modify: `src/firewall.ts:53`, `src/firewall.ts:73`
- Modify: `package.json` (scripts)

**Interfaces:**
- Produces: `export function safeEndStdin(child: ChildProcess, data: string): void` — attaches a no-op `'error'` listener to `child.stdin`, then ends it with `data`. Never throws.

- [ ] **Step 1: Add the test script to `package.json`**

In the `"scripts"` block, add a `test` entry (explicit file list — deterministic on Node 20, no glob dependency):

```json
    "typecheck": "tsc --noEmit",
    "test": "node --import tsx --test src/proc-io.test.ts src/net-iface.test.ts src/geolocation.test.ts"
```

(Keep the existing `predev`/`dev`/`build`/`start` entries unchanged; just add `test` after `typecheck`.)

- [ ] **Step 2: Write the failing test** — `src/proc-io.test.ts`

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { safeEndStdin } from './proc-io.js';

test('safeEndStdin does not throw when the child stdin is already destroyed', async () => {
  // `cat` exits immediately on a closed stdin; kill it to force the pipe shut,
  // reproducing the EPIPE/ERR_STREAM_DESTROYED that crashed the server.
  const child = spawn('cat');
  child.stdin.destroy();
  child.kill('SIGKILL');
  await new Promise((r) => child.on('close', r));
  assert.doesNotThrow(() => safeEndStdin(child, 'data\n'));
});

test('safeEndStdin writes to a healthy child without throwing', async () => {
  const child = spawn('cat');
  assert.doesNotThrow(() => safeEndStdin(child, 'hello\n'));
  await new Promise((r) => child.on('close', r));
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `pnpm test`
Expected: FAIL — `Cannot find module './proc-io.js'` (helper not created yet).

- [ ] **Step 4: Create `src/proc-io.ts`**

```ts
import type { ChildProcess } from 'node:child_process';

/**
 * End a child process's stdin safely. The stream can already be destroyed
 * (the child was SIGKILLed by a watchdog timeout, or sudo exited on a wrong
 * password mid-write), in which case `end()` emits an 'error' on the stdin
 * stream. Without a listener that error is unhandled and crashes the process.
 * A no-op 'error' listener absorbs it; close/exit still drive the caller's
 * resolve/reject.
 */
export function safeEndStdin(child: ChildProcess, data: string): void {
  if (!child.stdin) return;
  child.stdin.on('error', () => {});
  try {
    child.stdin.end(data);
  } catch {
    // stdin destroyed between the guard and the call — already handled above.
  }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pnpm test`
Expected: PASS — both `safeEndStdin` tests pass.

- [ ] **Step 6: Use the helper in `firewall.ts`**

Add the import near the top of `src/firewall.ts` (after the existing `node:*` imports):

```ts
import { safeEndStdin } from './proc-io.js';
```

In `validateSudo`, replace line 53:

```ts
    child.stdin.end(password + '\n');
```
with:
```ts
    safeEndStdin(child, password + '\n');
```

In `loadAnchorRules`, replace line 73:

```ts
    child.stdin.end(rules);
```
with:
```ts
    safeEndStdin(child, rules);
```

- [ ] **Step 7: Typecheck**

Run: `pnpm typecheck`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add package.json src/proc-io.ts src/proc-io.test.ts src/firewall.ts
git commit -m "fix(firewall): absorb stdin EPIPE so a bad sudo password can't crash the server"
```

---

### Task 2: Fix `routes.ts` local-IP selection

The inner `break` only exits the inner loop; the outer interface loop keeps going, so `localIP` ends up as the first IPv4 of the **last** non-internal interface — with VPN (`utun`) or Docker (`bridge100`) up, the reported "local IP" can be a VPN/Docker address. Extract a pure selector, test it, and use it.

**Files:**
- Create: `src/net-iface.ts`
- Create: `src/net-iface.test.ts`
- Modify: `src/routes.ts:247-257`

**Interfaces:**
- Consumes: the return type of `node:os` `networkInterfaces()`.
- Produces: `export function pickPrimaryIPv4(nets: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string` — returns the primary external IPv4, preferring `en*` (Wi-Fi/Ethernet) and skipping `utun`/`bridge`/`llw`/`awdl`; falls back to `'127.0.0.1'`.

- [ ] **Step 1: Write the failing test** — `src/net-iface.test.ts`

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickPrimaryIPv4 } from './net-iface.js';

const v4 = (address: string, internal = false) =>
  ({ address, family: 'IPv4', internal, netmask: '', mac: '', cidr: null } as any);

test('prefers en0 over VPN/Docker interfaces regardless of enumeration order', () => {
  const nets = {
    lo0: [v4('127.0.0.1', true)],
    en0: [v4('192.168.1.20')],
    utun3: [v4('10.8.0.2')],
    bridge100: [v4('192.168.64.1')],
  };
  assert.equal(pickPrimaryIPv4(nets), '192.168.1.20');
});

test('falls back to any external IPv4 when no en* exists', () => {
  const nets = { eth0: [v4('172.16.0.5')] };
  assert.equal(pickPrimaryIPv4(nets), '172.16.0.5');
});

test('skips virtual interfaces and falls back to loopback when nothing else', () => {
  const nets = { lo0: [v4('127.0.0.1', true)], utun0: [v4('10.0.0.1')], bridge0: [v4('192.168.64.1')] };
  assert.equal(pickPrimaryIPv4(nets), '127.0.0.1');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test`
Expected: FAIL — `Cannot find module './net-iface.js'`.

- [ ] **Step 3: Create `src/net-iface.ts`**

```ts
import type * as os from 'node:os';

// Virtual / tunnel interfaces that should never be reported as the host's
// primary LAN address: VPN tunnels (utun), bridges (Docker/VMs), and Apple's
// link-local helper interfaces (llw, awdl).
const VIRTUAL_PREFIXES = ['utun', 'bridge', 'llw', 'awdl', 'ipsec', 'gif', 'stf'];

function isVirtual(name: string): boolean {
  return VIRTUAL_PREFIXES.some((p) => name.startsWith(p));
}

/**
 * Pick the host's primary external IPv4. Prefers physical `en*` interfaces
 * (Wi-Fi/Ethernet on macOS), then any other non-virtual external IPv4, and
 * finally falls back to loopback. Deterministic regardless of the order
 * `networkInterfaces()` returns interfaces in.
 */
export function pickPrimaryIPv4(nets: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string {
  let preferred: string | null = null; // en*
  let fallback: string | null = null;  // any other non-virtual external

  for (const name of Object.keys(nets)) {
    if (isVirtual(name)) continue;
    for (const net of nets[name] ?? []) {
      if (net.family !== 'IPv4' || net.internal) continue;
      if (name.startsWith('en')) {
        if (!preferred) preferred = net.address;
      } else if (!fallback) {
        fallback = net.address;
      }
    }
  }
  return preferred ?? fallback ?? '127.0.0.1';
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test`
Expected: PASS — all three `pickPrimaryIPv4` tests pass.

- [ ] **Step 5: Use it in `routes.ts`**

Add to the imports at the top of `src/routes.ts`:

```ts
import { pickPrimaryIPv4 } from './net-iface.js';
```

Replace the block at `src/routes.ts:247-257`:

```ts
  // Get local IP
  const nets = networkInterfaces();
  let localIP = '127.0.0.1';
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] ?? []) {
      if (net.family === 'IPv4' && !net.internal) {
        localIP = net.address;
        break;
      }
    }
  }
```
with:
```ts
  // Get local IP (prefers en*, skips VPN/Docker/virtual interfaces)
  const localIP = pickPrimaryIPv4(networkInterfaces());
```

If `networkInterfaces` is now otherwise unused, leave the existing import as-is only if other code uses it; otherwise it is still used here, so keep the import.

- [ ] **Step 6: Typecheck**

Run: `pnpm typecheck`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/net-iface.ts src/net-iface.test.ts src/routes.ts
git commit -m "fix(host-info): pick primary en* IPv4, not the last interface (VPN/Docker)"
```

---

### Task 3: Fix `geolocation.ts` rate-limiter race

`lastBatchTime` is read (line 98), awaited, then written (line 104) with no mutual exclusion, so two concurrent callers both pass the gate and `fetch` ip-api.com in the same instant — risking the 45 req/min free-tier limit (→ 429s, silently dropped geo). `lookupSingleIP` bypasses the limiter entirely. Fix by serializing every outbound batch through one promise chain (mirroring the existing `serialize()` in `block-store.ts`).

**Files:**
- Modify: `src/geolocation.ts`
- Create: `src/geolocation.test.ts`

**Interfaces:**
- Produces (module-internal): `function rateLimitedFetch(input, init): Promise<Response>` — serializes calls and enforces `MIN_BATCH_INTERVAL` spacing before each.

- [ ] **Step 1: Write the failing test** — `src/geolocation.test.ts`

This test pins the core property (serialized ops never overlap) using a fast, deterministic shared-counter check — no real timers, no network.

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { __testSerialize } from './geolocation.js';

test('serialized operations never overlap', async () => {
  let active = 0;
  let maxActive = 0;
  const op = async () => {
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
  };
  await Promise.all([
    __testSerialize(op),
    __testSerialize(op),
    __testSerialize(op),
  ]);
  assert.equal(maxActive, 1); // strictly one at a time
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test`
Expected: FAIL — `__testSerialize` is not exported yet.

- [ ] **Step 3: Add the serializer to `geolocation.ts`**

Find the existing rate-limit constants/state near the top of the file (`lastBatchTime`, `MIN_BATCH_INTERVAL`). Just below them, add:

```ts
// Serialize all outbound ip-api.com requests through one chain so concurrent
// callers can't both clear the rate-limit gate at once. Mirrors block-store's
// serialize(). Spacing is reserved BEFORE awaiting the fetch (set lastBatchTime
// to the scheduled send time), not after, so the next op waits the full window.
let geoChain: Promise<unknown> = Promise.resolve();
function serializeGeo<T>(op: () => Promise<T>): Promise<T> {
  const run = geoChain.then(async () => {
    const elapsed = Date.now() - lastBatchTime;
    if (elapsed < MIN_BATCH_INTERVAL) {
      await new Promise((r) => setTimeout(r, MIN_BATCH_INTERVAL - elapsed));
    }
    lastBatchTime = Date.now();
    return op();
  });
  geoChain = run.catch(() => {});
  return run;
}

// Test-only handle (not part of the public API).
export const __testSerialize = serializeGeo;
```

- [ ] **Step 4: Route the batch fetch through the serializer**

In `lookupIPs`, replace the per-batch spacing+fetch block (`src/geolocation.ts:96-141` region). The current loop body manually waits then fetches:

```ts
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
```

Change the opening so the spacing+fetch run inside `serializeGeo` (the manual `elapsed`/`lastBatchTime` lines move into the serializer and are deleted here):

```ts
  for (const batch of batches) {
    try {
      const response = await serializeGeo(() =>
        fetch('http://ip-api.com/batch?fields=status,country,countryCode,city,isp,lat,lon,query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batch),
          signal: AbortSignal.timeout(5000),
        })
      );

      if (!response.ok) continue;
```

Leave the rest of the loop body (the `data` parsing, cache writes, `catch`) unchanged.

- [ ] **Step 5: Route `lookupSingleIP` through the same limiter**

Open `src/geolocation.ts:48` (`lookupSingleIP`). Wrap its outbound `fetch` to ip-api.com in `serializeGeo(() => fetch(...))` exactly as in Step 4 (keep its existing cache check, success parsing, and error handling). The single-IP endpoint is `http://ip-api.com/json/<ip>?fields=...`; only the `fetch(...)` call moves inside `serializeGeo`. Do not change its return type or cache behavior.

- [ ] **Step 6: Run tests + typecheck**

Run: `pnpm test && pnpm typecheck`
Expected: PASS (serialize test green) and no type errors.

- [ ] **Step 7: Commit**

```bash
git add src/geolocation.ts src/geolocation.test.ts
git commit -m "fix(geo): serialize ip-api requests so concurrent callers respect the rate limit"
```

---

### Task 4: Fix `app.js` live-traffic correctness (truncation + leak + stale baseline)

Three intertwined bugs on the SSE traffic path: (a) `e.bytesIn | 0` truncates to 32-bit signed → throughput corrupts past ~2.1 GB; (b) `liveTraffic` is only ever `.set()`, never pruned → unbounded memory growth; (c) a reused 5-tuple keeps a stale (large) baseline → `Math.max(0, small - large) = 0` silently drops traffic. All three live in `connectTrafficStream` + `fetchConnections`. No module system yet → inline fix + manual verification.

**Files:**
- Modify: `public/app.js:1122` (truncation + reset handling), `public/app.js:1113-1121` (stale baseline), `public/app.js:505` (prune)

- [ ] **Step 1: Fix the byte storage + counter-reset (stale baseline) in the delta loop**

In `connectTrafficStream`, replace the per-entry block at `public/app.js:1115-1122`:

```js
      const prevBytes = liveTraffic.get(e.key);
      if (prevBytes) {
        const drx = Math.max(0, e.bytesIn - prevBytes.bytesIn);
        const dtx = Math.max(0, e.bytesOut - prevBytes.bytesOut);
        rxBytesPerSec += drx;
        txBytesPerSec += dtx;
      }
      liveTraffic.set(e.key, { bytesIn: e.bytesIn | 0, bytesOut: e.bytesOut | 0 });
```
with:
```js
      const bytesIn = Number(e.bytesIn) || 0;   // no `| 0` — that truncates to 32-bit signed (wraps past ~2.1 GB)
      const bytesOut = Number(e.bytesOut) || 0;
      const prevBytes = liveTraffic.get(e.key);
      if (prevBytes) {
        // A *decreasing* counter means nettop reset / the 5-tuple was reused:
        // count the fresh absolute value rather than dropping the delta to 0.
        const drx = bytesIn < prevBytes.bytesIn ? bytesIn : bytesIn - prevBytes.bytesIn;
        const dtx = bytesOut < prevBytes.bytesOut ? bytesOut : bytesOut - prevBytes.bytesOut;
        rxBytesPerSec += Math.max(0, drx);
        txBytesPerSec += Math.max(0, dtx);
      }
      liveTraffic.set(e.key, { bytesIn, bytesOut });
```

(The `formatBytes(e.bytesIn)` / `formatBytes(e.bytesOut)` row-patch lines just below stay unchanged — they already use the untruncated value.)

- [ ] **Step 2: Prune `liveTraffic` against live keys on each poll**

In `fetchConnections`, immediately after `lastData = data;` (`public/app.js:505`), insert:

```js
    // Prune liveTraffic to the currently-live connections so the Map can't grow
    // unbounded as ephemeral sockets (TIME_WAIT, short UDP, browser conns) churn.
    const liveKeys = new Set();
    for (const p of data) for (const c of p.connections) liveKeys.add(c.trafficKey);
    for (const k of liveTraffic.keys()) if (!liveKeys.has(k)) liveTraffic.delete(k);
```

- [ ] **Step 3: Verify it typechecks-by-running (no TS for `public/`)**

Run: `pnpm dev` and load `http://localhost:3847`. Open DevTools console — expect **no errors**.

- [ ] **Step 4: Manual verification checklist**

- Connection list renders and per-row `↓/↑` byte counters update live.
- In DevTools console run `liveTraffic.size` a few times over ~30 s while connections churn — it should track the visible connection count, **not climb without bound**.
- Trigger a large transfer (e.g. download a multi-GB file) — Download/Upload MB numbers and the sparklines stay positive and sane (no negative/garbage values).
- Throughput attributes to the right connection (start a download, watch its row).

- [ ] **Step 5: Commit**

```bash
git add public/app.js
git commit -m "fix(traffic): stop 32-bit byte truncation, prune liveTraffic, handle counter resets"
```

---

### Task 5: Fix `app.js` stream-health status + idle decay

Two more SSE bugs: the status badge is hard-coded to `'streaming · live'` by the 2 s poll regardless of SSE health (a dead stream shows green "live" while RX/TX are frozen), and `pushThroughput` only fires on a delta — so when traffic stops, the numbers/sparklines **freeze at the last value** instead of decaying to 0. Fix with a shared `streamHealthy` flag and a visibility-gated idle-decay interval.

**Files:**
- Modify: `public/app.js:67-69` (module state), `public/app.js:506` (poll status), `public/app.js:1102-1139` (SSE handlers)

- [ ] **Step 1: Add module-scope stream state**

Near the other state declarations (after `public/app.js:68`, by the `liveTraffic` line), add:

```js
let streamHealthy = false;   // true once the SSE stream is delivering deltas
let lastDeltaAt = 0;         // ms timestamp of the last delta (for idle decay)
```

- [ ] **Step 2: Make the poll status reflect real stream health**

In `fetchConnections`, replace `public/app.js:506`:

```js
    statusText.textContent = 'streaming · live';
```
with:
```js
    statusText.textContent = streamHealthy ? 'streaming · live' : 'poll · stream offline';
    statusText.classList.toggle('err', !streamHealthy);
```

(Keep the existing `statusText.classList.remove('err', 'wait');` line directly below — it is harmless; the `toggle` above sets the correct final state. If you prefer, remove the now-redundant `remove('err', ...)`; either is fine.)

- [ ] **Step 3: Mark health in the SSE handlers**

In `connectTrafficStream`, inside the `'delta'` listener, set health at the top of the callback (right after the `Array.isArray(arr)` guard, before the `for` loop):

```js
    streamHealthy = true;
    lastDeltaAt = Date.now();
```

Replace the empty `'error'` handler at `public/app.js:1136-1138`:

```js
  es.addEventListener('error', () => {
    // EventSource reconnects on its own.
  });
```
with:
```js
  es.addEventListener('error', () => {
    // EventSource auto-reconnects, but surface the degraded state meanwhile.
    streamHealthy = false;
  });
  es.addEventListener('open', () => { streamHealthy = true; });
```

- [ ] **Step 4: Add the visibility-gated idle-decay ticker**

At the end of `connectTrafficStream` (after the listeners), add:

```js
  // Decay the throughput readout to 0 when no deltas arrive (the server only
  // emits a delta when traffic > 0). Paused while the tab is hidden.
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    if (lastDeltaAt && Date.now() - lastDeltaAt >= 1500) {
      pushThroughput(0, 0);
      lastDeltaAt = Date.now(); // keep ticking 0s while idle, but only once/window
    }
  }, 1000);
```

- [ ] **Step 5: Manual verification checklist**

Run: `pnpm dev` → `http://localhost:3847`
- With traffic flowing, badge reads `streaming · live`.
- Stop all network traffic (or `kill` the SSE by blocking the endpoint) — within ~2 s the Download/Upload numbers fall to `0.00` and the sparklines flatten, instead of freezing at the last value.
- Simulate a dead stream: in DevTools, run `es?.close?.()` is not needed — instead temporarily return 500 from `/api/traffic-stream`, reload — the badge shows `poll · stream offline` with the `.err` style; RX/TX no longer claim "live".
- No console errors.

- [ ] **Step 6: Commit**

```bash
git add public/app.js
git commit -m "fix(traffic): show real SSE health and decay throughput to zero when idle"
```

---

### Task 6: Accessibility — focus ring, reduced-motion, contrast tokens

The weakest, cheapest axis. No global focus indicator anywhere (`button { border:0 }`, no `:focus-visible`), the radar + `pulse`/`spin` animate continuously with no `prefers-reduced-motion` guard, and `--ink-dim`/`--ink-mute` fail WCAG AA on the dark background. CSS-only.

**Files:**
- Modify: `public/style.css` (tokens at `:root` ~lines 14-16; add focus + motion rules)

- [ ] **Step 1: Lift the two low-contrast tokens**

In `:root` (`public/style.css:14-16`), raise lightness so body/meta text clears WCAG AA on the `L≈0.13` background:

```css
  --ink-dim:   oklch(0.58 0.004 85);
  --ink-mute:  oklch(0.40 0.004 85);
```
→
```css
  --ink-dim:   oklch(0.72 0.004 85);
  --ink-mute:  oklch(0.60 0.004 85);
```

- [ ] **Step 2: Add a global focus-visible ring**

Directly after the `button { ... }` reset at `public/style.css:46`, add:

```css
/* Accessibility: visible keyboard focus on every interactive element
   (the button reset above strips the UA outline). */
:focus-visible {
  outline: 2px solid var(--ice);
  outline-offset: 2px;
  border-radius: 3px;
}
:focus:not(:focus-visible) { outline: none; }
```

- [ ] **Step 3: Add a `prefers-reduced-motion` guard**

At the end of `public/style.css`, append:

```css
/* Respect reduced-motion: stop continuous, non-essential animation. The radar
   sweep is driven from JS and gated separately (see app.js). */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
    scroll-behavior: auto !important;
  }
}
```

- [ ] **Step 4: Gate the radar animation loop in JS**

The radar is canvas + `requestAnimationFrame`, so CSS can't stop it. Find the radar frame scheduler (search `public/app.js` for `scheduleRadarFrame` / `requestAnimationFrame` in the radar section, ~`public/app.js:1162+`). At the top of the function that schedules/draws each frame, add an early guard so reduced-motion users get a single static frame instead of the continuous sweep:

```js
  // Honor reduced-motion: draw one static frame, don't run the sweep loop.
  if (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) {
    drawRadarOnce(); // draw current targets once; do not re-schedule
    return;
  }
```

If a single static-draw helper does not already exist, reuse the existing per-frame draw call but simply `return` before the `requestAnimationFrame(...)` re-schedule line (i.e. render once, never loop). Keep the change to the minimum: one guard at the scheduler entry.

- [ ] **Step 5: Manual verification checklist**

- Tab through the toolbar/search/buttons — a cyan focus ring is clearly visible on each.
- macOS System Settings → Accessibility → Display → **Reduce Motion ON**, reload: the radar sweep/pulse stop (static frame), the refresh spinner doesn't spin.
- In Chrome DevTools → Rendering → "Emulate CSS prefers-reduced-motion: reduce" gives the same result without changing OS settings.
- Spot-check contrast with DevTools' color picker on `.row .meta` and the small section labels — AA (≥ 4.5:1 for text) for body copy.

- [ ] **Step 6: Commit**

```bash
git add public/style.css public/app.js
git commit -m "a11y: add focus-visible ring, prefers-reduced-motion guard, lift contrast tokens"
```

---

### Task 7: Accessibility — keyboard-operable connection rows

The core interaction — expanding a process row — is a `<div data-action="toggle">` with no `tabindex`/`role`/keyboard handler, so the app can't be driven from the keyboard. Add semantics to the row template and a keydown handler mirroring the existing click delegation.

**Files:**
- Modify: `public/app.js:293` (row template), and the row click-delegation handler

- [ ] **Step 1: Add roles/state to the row template**

At `public/app.js:293`, the row is rendered as:

```js
    <div class="row ${proc.isSystemProcess ? 'sys' : ''} ${expanded ? 'active' : ''}" data-action="toggle" data-pid="${proc.pid}">
```
Add keyboard semantics:
```js
    <div class="row ${proc.isSystemProcess ? 'sys' : ''} ${expanded ? 'active' : ''}" data-action="toggle" data-pid="${proc.pid}" tabindex="0" role="button" aria-expanded="${expanded}">
```

- [ ] **Step 2: Add a keydown handler mirroring the click toggle**

Find the existing delegated **click** handler that reacts to `[data-action="toggle"]` (search `public/app.js` for `data-action` / `closest('.row')` / `dataset.pid`). Immediately after it is registered, add a sibling keydown handler on the same container so Enter/Space toggle the focused row:

```js
// Keyboard activation for process rows (Enter/Space), mirroring the click toggle.
queue.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const row = e.target.closest?.('.row[data-action="toggle"]');
  if (!row) return;
  e.preventDefault();            // Space must not scroll the page
  row.click();                   // reuse the existing click→toggle path
});
```

Replace `queue` with the actual container variable used by the existing click delegation (e.g. the `#queue` element handle). If clicks are delegated on `document`, attach this keydown to `document` too — match the existing pattern exactly.

- [ ] **Step 3: Manual verification checklist**

Run: `pnpm dev` → `http://localhost:3847`
- Press `/` (existing shortcut) then Escape/Tab into the list; Tab moves focus across rows (visible focus ring from Task 6).
- Enter or Space on a focused row expands/collapses it; `aria-expanded` flips (check in DevTools Elements).
- Screen reader (VoiceOver: ⌘F5) announces each row as a button with expanded/collapsed state.

- [ ] **Step 4: Commit**

```bash
git add public/app.js
git commit -m "a11y: make process rows keyboard-operable (tabindex/role/aria-expanded + Enter/Space)"
```

---

### Task 8: Accessibility — control labels, live region, modal focus-trap

Unlabeled icon/glyph controls, no live region for status, and modals that neither trap nor restore focus (and the confirm dialog has no Escape). Add `aria-label`s + a `role="status"` live region in the HTML, and a tiny shared focus-trap helper for the two overlays in `app.js`.

**Files:**
- Modify: `public/index.html` (control labels, status live region, canvas label)
- Modify: `public/app.js` (confirm + sudo overlays: `role="dialog"`, focus trap/restore, Esc on confirm)

- [ ] **Step 1: Label static controls + add the live region (index.html)**

In `public/index.html`, add `aria-label` to the interactive controls the audit flagged (match by existing `id`). Apply these (add only the attribute; leave everything else):

- `#searchInput` → `aria-label="Search connections"`
- `#blockedSearch` → `aria-label="Search blocked IPs"`
- `#sortSelect` → `aria-label="Sort processes"`
- `#refreshSelect` → `aria-label="Refresh interval"`
- `#refreshNowBtn` → `aria-label="Refresh now"`
- the radar `<canvas id="radar">` → `aria-hidden="true"` (decorative; its data is in the list)
- the status element backing `statusText` → add `role="status"` so updates are announced

Then make the connection-count / status text a polite live region. Find the element whose text is set as the connection count (and `statusText`'s container); add `aria-live="polite"` to the count element. If `statusText` already has `role="status"` it is implicitly live — do not double up `aria-live` on the same node.

- [ ] **Step 2: Add a focus-trap helper (app.js)**

Near the toast/overlay helpers (around `public/app.js:700`), add:

```js
// Minimal modal focus management: save the previously-focused element, trap
// Tab within the overlay, and restore focus on close. Returns a cleanup fn.
function trapFocus(overlay) {
  const prev = document.activeElement;
  const sel = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
  const onKey = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...overlay.querySelectorAll(sel)].filter((el) => !el.disabled && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  overlay.addEventListener('keydown', onKey);
  return () => {
    overlay.removeEventListener('keydown', onKey);
    if (prev && typeof prev.focus === 'function') prev.focus();
  };
}
```

- [ ] **Step 3: Apply it to the confirm dialog**

In the confirm-overlay builder (`public/app.js:713-729`): add dialog semantics to the overlay markup and wire the trap + Esc. Change the overlay element setup to include ARIA — after `overlay.className = 'confirm-overlay';` add:

```js
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
```

After `document.body.appendChild(overlay);` (line ~726), add:

```js
  const release = trapFocus(overlay);
  const close = () => { release(); overlay.remove(); };
  overlay.querySelector('.confirm-kill').focus(); // sensible initial focus
  document.addEventListener('keydown', function esc(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); document.removeEventListener('keydown', esc); }
  });
```

Then change the existing cancel/kill/click-outside handlers (lines 727-729) to call `close()` instead of `overlay.remove()`:

```js
  overlay.querySelector('.confirm-cancel').addEventListener('click', close);
  overlay.querySelector('.confirm-kill').addEventListener('click', () => { close(); onConfirm(); });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
```

- [ ] **Step 4: Apply it to the sudo dialog**

In the sudo-overlay builder (`public/app.js:735-773`): add the same `role="dialog"`/`aria-modal="true"` after `overlay.className = 'confirm-overlay';`. Wrap teardown with the trap: after `document.body.appendChild(overlay);` (line ~756) capture `const release = trapFocus(overlay);`, and in the existing `cancel`/`submit` paths call `release()` immediately before `overlay.remove()`. The existing `input.focus()` (auto-focus) and the input's Enter/Escape handling stay; they are already correct.

- [ ] **Step 5: Manual verification checklist**

Run: `pnpm dev` → `http://localhost:3847`
- VoiceOver (⌘F5): search box, selects, glyph buttons announce their labels (not "button" / "wastebasket").
- Trigger a system-process kill → confirm dialog: focus lands inside it, Tab cycles only within the dialog, **Escape closes it**, and focus returns to the triggering row.
- Trigger a block → sudo dialog: Tab is trapped, Escape cancels, focus restores afterwards.
- Status badge changes are announced by the screen reader (role="status").

- [ ] **Step 6: Commit**

```bash
git add public/index.html public/app.js
git commit -m "a11y: label controls, add status live region, trap & restore focus in modals"
```

---

### Task 9: Cleanups — dead `tempC`, shared `ActionResult`, stale docs

Verified-safe housekeeping. `tempC`/`TEMP_C` is always `null` and **no frontend code reads it** (confirmed: the only `temp` matches in `public/` are CSS `grid-template`). `firewall`/`kill`/`vt`/`delete` all return `{ success, message }` — give it one named type. `CLAUDE.md` still describes a `globe.gl` 3D globe that does not exist (the app uses a 2D canvas radar + `topojson-client`).

**Files:**
- Modify: `src/system-health.ts` (remove `tempC`/`TEMP_C`)
- Modify: `src/types.ts` (add `ActionResult`)
- Modify: `src/firewall.ts` (use `ActionResult` in the two return signatures)
- Modify: `CLAUDE.md` (drop globe.gl/Three.js references)

- [ ] **Step 1: Remove dead `tempC`**

In `src/system-health.ts`: delete the `tempC: number | null;` field from the `SystemHealth` interface (line 18), delete the `TEMP_C` const + its comment (lines 61-66), and remove `tempC: TEMP_C,` from the returned object (line 93).

- [ ] **Step 2: Confirm nothing breaks**

Run: `pnpm typecheck`
Expected: no errors (no consumer referenced `tempC`).

- [ ] **Step 3: Add the shared `ActionResult` type**

In `src/types.ts`, add:

```ts
/** Standard result for state-changing actions (block/unblock/kill/etc.). */
export interface ActionResult {
  success: boolean;
  message: string;
}
```

- [ ] **Step 4: Use it in `firewall.ts`**

Add `ActionResult` to the existing `./types.js` import in `src/firewall.ts` (or add an import if none exists). Change the two return types:

```ts
export async function blockIP(ip: string, password: string): Promise<{ success: boolean; message: string }> {
```
→
```ts
export async function blockIP(ip: string, password: string): Promise<ActionResult> {
```
and the same for `unblockIP` (line 174). Function bodies are unchanged.

- [ ] **Step 5: Fix the stale `CLAUDE.md` docs**

In `CLAUDE.md`, under **Stack**, remove the line `- globe.gl (Three.js) loaded from CDN — not bundled`. Under **Frontend (`public/`)**, replace the `3D globe (globe.gl): ...` bullet with one describing the actual UI: `- 2D canvas radar: rotating sweep + country pins (`topojson-client` for coastlines), gated by Resize/Intersection/visibility observers`. Under **External Services**, remove the `unpkg.com CDN — globe.gl and three-globe assets` line (keep it only if `topojson` is loaded from a CDN — verify against `index.html`; otherwise delete).

- [ ] **Step 6: Typecheck + commit**

Run: `pnpm typecheck`
Expected: no errors.

```bash
git add src/system-health.ts src/types.ts src/firewall.ts CLAUDE.md
git commit -m "chore: drop dead tempC, add shared ActionResult type, fix stale globe.gl docs"
```

---

## Final Verification

After all tasks:

- [ ] `pnpm test` — all backend unit tests pass.
- [ ] `pnpm typecheck` — clean.
- [ ] `pnpm dev` — app loads at `http://localhost:3847` with **no console errors**; full manual pass: connection list live-updates, expand a row via keyboard, kill (confirm dialog Esc + focus restore), block (sudo dialog), throughput decays to 0 when idle, badge reflects stream health, reduced-motion stops the radar.
- [ ] Per the user's workflow rule: run `/code-review` and `/security-review` before any push.

## Self-Review Notes

- **Spec coverage:** all 8 confirmed bugs (firewall stdin, byte truncation, liveTraffic leak, stale baseline, idle-freeze, stream-down status, geo race, localIP) → Tasks 1-5; a11y top items (focus ring, reduced-motion, contrast, keyboard rows, labels, live region, modal focus-trap) → Tasks 6-8; zero-risk cleanups → Task 9. Usability quick wins explicitly deferred to Phase 1b (noted under File Structure).
- **Type consistency:** `safeEndStdin` (Task 1), `pickPrimaryIPv4` (Task 2), `serializeGeo`/`__testSerialize` (Task 3), `trapFocus` (Task 8), `ActionResult` (Task 9), `streamHealthy`/`lastDeltaAt` (Task 5) — each defined before use; names consistent across tasks.
- **Known approximations:** Tasks 6/7/8 reference search-and-locate for the radar scheduler, the row click-delegation container, and a few `index.html` element ids (rendered dynamically or not yet read line-for-line). Each step names the exact symbol/selector to find and gives complete drop-in code; the implementer confirms the surrounding variable name before pasting.
