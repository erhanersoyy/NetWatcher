# Blocked-State Re-apply on Launch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a reboot wipes the macOS `pf` ruleset, detect that persisted blocked IPs are no longer enforced and let the user re-apply them all with a single sudo entry.

**Architecture:** Detect drift server-side without sudo by comparing the system boot time (`sysctl -n kern.boottime`) against a per-IP `appliedBoot` marker stored on each `BlockRecord`. Surface stale blocks via additive fields on the existing `/api/block-history` response; a banner in the blocked panel triggers a new `POST /api/reapply` that re-adds every active IP to the `pf` table under one sudo prompt.

**Tech Stack:** Node.js + TypeScript (strict) + Express 5 backend; vanilla ES-module frontend; Node's built-in test runner. macOS-only (`sysctl`, `pfctl`).

## Global Constraints

- TypeScript strict; **no `any`** — use `unknown` + narrowing.
- ES modules only (`import`/`export`), never CommonJS.
- Prefer early returns over nested conditionals; prefer minimal code.
- All comments and docs in English.
- All `pfctl`/`sudo`/`sysctl` calls are argv-form `execFile`/`spawn` — never a shell string.
- The sudo password is supplied per-request, validated via `validateSudo`, and never stored. No new password storage. No passwordless-sudo.
- `GET /api/blocked` keeps its existing `string[] | null` shape (do not change it). New stale fields go on `GET /api/block-history` only, additively.
- Testing posture (from the spec): unit-test **pure functions only** (`parseBootSec`, `countStaleBlocks`) and the FS-isolated block-store round-trip. The live `pfctl`/`sudo` path and HTTP routes are integration/runtime-verified, not unit-tested — consistent with the existing suite.
- Run `pnpm typecheck` after each task's edits; `pnpm test` runs `src/**/*.test.ts` + `public/**/*.test.js`.
- Conventional commits (`feat:`, `fix:`, `docs:`).

---

## File Structure

- **Create `src/boot-info.ts`** — `parseBootSec` (pure) + `getBootId` (cached `sysctl` read). The only new module.
- **Modify `src/types.ts`** — add `appliedBoot?: number | null` to `BlockRecord`.
- **Modify `src/block-store.ts`** — lazy `storePath()` (env-overridable for tests); `recordBlock` gains an `appliedBoot` param (default `null`); add `markReapplied`; add pure `countStaleBlocks`.
- **Modify `src/firewall.ts`** — `blockIP` stamps the new record's `appliedBoot`; add `reapplyBlocks`.
- **Modify `src/routes.ts`** — `/api/block-history` returns `stale`/`staleCount`; add `POST /api/reapply`.
- **Modify frontend** — `public/js/state.js` (state fields), `public/js/api.js` (parse stale + `reapplyBlocks` fetcher), `public/js/modals.js` (banner in `renderBlockedPanel`), `public/js/actions.js` (delegated handler + `reapplyBlocksAction`), `public/style.css` (banner styles).
- **Create tests** — `src/boot-info.test.ts`, `src/block-store.test.ts`, `src/firewall.test.ts`.

Order: Task 1 → 2 → 3 → 4 → 5 (each depends only on earlier tasks).

---

## Task 1: `boot-info.ts` — reboot detection primitive

**Files:**
- Create: `src/boot-info.ts`
- Test: `src/boot-info.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `parseBootSec(output: string): number | null`; `getBootId(): Promise<number | null>`.

- [ ] **Step 1: Write the failing test**

Create `src/boot-info.test.ts`:

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseBootSec } from './boot-info.js';

test('parseBootSec extracts the epoch second from kern.boottime output', () => {
  assert.equal(parseBootSec('{ sec = 1719300000, usec = 0 } Tue Jun 25 10:00:00 2026'), 1719300000);
});

test('parseBootSec tolerates no spaces around the equals sign', () => {
  assert.equal(parseBootSec('{ sec=1719300123, usec=5 }'), 1719300123);
});

test('parseBootSec returns null on malformed or empty input', () => {
  assert.equal(parseBootSec(''), null);
  assert.equal(parseBootSec('no numbers here'), null);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test 2>&1 | grep -A2 boot-info`
Expected: FAIL — `Cannot find module './boot-info.js'` (module not created yet).

- [ ] **Step 3: Implement `boot-info.ts`**

Create `src/boot-info.ts`:

```ts
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

// Parse the `sec = <epoch>` integer out of `sysctl -n kern.boottime` output,
// e.g. "{ sec = 1719300000, usec = 0 } Tue Jun 25 ..." -> 1719300000.
export function parseBootSec(output: string): number | null {
  const m = /sec\s*=\s*(\d+)/.exec(output);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

// System boot time in epoch seconds, read without sudo. Cached for the
// process lifetime — boot time is constant for a given OS boot. Only a
// successful read is cached, so a transient failure is retried next call.
// Returns null if sysctl is unavailable or its output can't be parsed
// (defense-in-depth; kern.boottime is world-readable on macOS).
let cached: number | null = null;
export async function getBootId(): Promise<number | null> {
  if (cached !== null) return cached;
  try {
    const { stdout } = await execFileAsync('sysctl', ['-n', 'kern.boottime'], { timeout: 5000 });
    const sec = parseBootSec(stdout);
    if (sec !== null) cached = sec;
    return sec;
  } catch {
    return null;
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test 2>&1 | grep -A2 boot-info`
Expected: PASS — 3 boot-info tests pass.

- [ ] **Step 5: Typecheck**

Run: `pnpm typecheck`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/boot-info.ts src/boot-info.test.ts
git commit -m "feat(firewall): add boot-info — read system boot time without sudo"
```

---

## Task 2: `block-store.ts` — per-IP `appliedBoot`, stale count, re-apply marker

**Files:**
- Modify: `src/types.ts:55-61` (BlockRecord)
- Modify: `src/block-store.ts`
- Test: `src/block-store.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `BlockRecord.appliedBoot?: number | null`
  - `recordBlock(ip, meta, appliedBoot?: number | null): Promise<void>` (param added, defaults `null`)
  - `markReapplied(ips: string[], bootId: number): Promise<void>`
  - `countStaleBlocks(active: BlockRecord[], currentBoot: number): number` (pure)

- [ ] **Step 1: Add `appliedBoot` to `BlockRecord`**

In `src/types.ts`, change the `BlockRecord` interface (lines 55-61) to:

```ts
export interface BlockRecord {
  ip: string;
  country: string | null;
  countryCode?: string | null;
  isp?: string | null;
  blockedAt: number;
  /** Boot epoch-second in which this IP was last added to the pf table.
   *  Stale (not enforced) when it differs from the current boot id. */
  appliedBoot?: number | null;
}
```

- [ ] **Step 2: Write the failing tests**

Create `src/block-store.test.ts`:

```ts
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recordBlock, markReapplied, getBlockHistory, countStaleBlocks } from './block-store.js';
import type { BlockRecord } from './types.js';

// storePath() reads NETWATCHER_DATA_DIR lazily, so pointing it at a temp dir
// keeps these tests off the real data/blocks.json.
let dir: string;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'nw-store-'));
  process.env.NETWATCHER_DATA_DIR = dir;
});
after(async () => {
  delete process.env.NETWATCHER_DATA_DIR;
  await rm(dir, { recursive: true, force: true });
});

const rec = (ip: string, appliedBoot: number | null): BlockRecord =>
  ({ ip, country: null, blockedAt: 0, appliedBoot });

test('countStaleBlocks: empty active -> 0', () => {
  assert.equal(countStaleBlocks([], 100), 0);
});

test('countStaleBlocks: all applied this boot -> 0', () => {
  assert.equal(countStaleBlocks([rec('1.1.1.1', 100), rec('2.2.2.2', 100)], 100), 0);
});

test('countStaleBlocks: previous-boot and undefined markers count as stale', () => {
  const active = [rec('1.1.1.1', 100), rec('2.2.2.2', 99), { ip: '3.3.3.3', country: null, blockedAt: 0 }];
  assert.equal(countStaleBlocks(active, 100), 2);
});

test('recordBlock persists appliedBoot; markReapplied updates only named IPs', async () => {
  await recordBlock('1.1.1.1', { country: null }, 50);
  await recordBlock('2.2.2.2', { country: null }, 50);
  let active = (await getBlockHistory()).active;
  assert.equal(active.find((r) => r.ip === '1.1.1.1')?.appliedBoot, 50);

  await markReapplied(['1.1.1.1'], 77);
  active = (await getBlockHistory()).active;
  assert.equal(active.find((r) => r.ip === '1.1.1.1')?.appliedBoot, 77);
  assert.equal(active.find((r) => r.ip === '2.2.2.2')?.appliedBoot, 50);
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `pnpm test 2>&1 | grep -A2 block-store`
Expected: FAIL — `markReapplied`/`countStaleBlocks` are not exported yet (import error or assertion failure).

- [ ] **Step 4: Make the store path env-overridable (lazy)**

In `src/block-store.ts`, replace the path constants (lines 6-9):

```ts
const __dirname = dirname(fileURLToPath(import.meta.url));
// src/ (dev via tsx) or dist/ (built) → ../data/blocks.json at project root.
const DATA_DIR = join(__dirname, '..', 'data');
const STORE_PATH = join(DATA_DIR, 'blocks.json');
```

with:

```ts
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
```

Then update the three call sites that used the constants:

In `readStore()` change `readFile(STORE_PATH, 'utf8')` to `readFile(storePath(), 'utf8')`.

In `writeStore()` change:

```ts
async function writeStore(data: StoreShape): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true });
  const tmp = STORE_PATH + '.tmp';
  await writeFile(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  await rename(tmp, STORE_PATH);
}
```

to:

```ts
async function writeStore(data: StoreShape): Promise<void> {
  const path = storePath();
  await mkdir(dirname(path), { recursive: true });
  const tmp = path + '.tmp';
  await writeFile(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  await rename(tmp, path);
}
```

(`dirname` is already imported from `node:path` on line 2.)

- [ ] **Step 5: Add the `appliedBoot` param, `markReapplied`, and `countStaleBlocks`**

In `src/block-store.ts`, change `recordBlock`'s signature and the record it writes:

```ts
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
```

Add these two exports (place them after `recordUnblock`):

```ts
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
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pnpm test 2>&1 | grep -A2 block-store`
Expected: PASS — all 4 block-store tests pass.

- [ ] **Step 7: Typecheck**

Run: `pnpm typecheck`
Expected: no output, exit 0. (`recordBlock`'s new param defaults to `null`, so the existing `firewall.ts` callers still compile.)

- [ ] **Step 8: Commit**

```bash
git add src/types.ts src/block-store.ts src/block-store.test.ts
git commit -m "feat(firewall): track per-IP appliedBoot; add markReapplied + countStaleBlocks"
```

---

## Task 3: `firewall.ts` — stamp `appliedBoot` on block; add `reapplyBlocks`

**Files:**
- Modify: `src/firewall.ts`
- Test: `src/firewall.test.ts`

**Interfaces:**
- Consumes: `getBootId` (Task 1); `markReapplied`, `recordBlock(…, appliedBoot)` (Task 2); existing `validateSudo`, `ensureAnchor`, `isBlockableIP`, `execFileAsync`, `ANCHOR`, `TABLE`.
- Produces: `reapplyBlocks(ips: string[], password: string): Promise<{ success: boolean; applied: string[]; failed: { ip: string; message: string }[]; message?: string }>`.

- [ ] **Step 1: Write the failing test**

Create `src/firewall.test.ts`:

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reapplyBlocks } from './firewall.js';

// An empty password must short-circuit BEFORE any sudo/pfctl spawn, so this
// test is safe to run in CI with no privileges.
test('reapplyBlocks rejects an empty password without spawning sudo', async () => {
  const r = await reapplyBlocks(['1.2.3.4'], '');
  assert.equal(r.success, false);
  assert.equal(r.applied.length, 0);
  assert.match(r.message ?? '', /password required/i);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test 2>&1 | grep -A2 firewall`
Expected: FAIL — `reapplyBlocks` is not exported yet.

- [ ] **Step 3: Wire `getBootId` + `markReapplied` imports and stamp `blockIP`**

In `src/firewall.ts`, update the two imports (lines 5-6 area):

```ts
import { recordBlock, recordUnblock, markReapplied } from './block-store.js';
import { lookupSingleIP } from './geolocation.js';
import { getBootId } from './boot-info.js';
```

In `blockIP`, replace the fire-and-forget record block (the `void (async () => { … })()` block, lines ~157-168) with one that stamps the current boot:

```ts
    // Record metadata out-of-band — pfctl's table has no notion of timestamps/country.
    // Stamp appliedBoot = current boot so this just-added IP is not flagged stale.
    void (async () => {
      const bootId = await getBootId();
      try {
        const geo = await lookupSingleIP(ip);
        await recordBlock(ip, {
          country: geo?.country ?? null,
          countryCode: geo?.countryCode ?? null,
          isp: geo?.isp ?? null,
        }, bootId);
      } catch {
        await recordBlock(ip, { country: null }, bootId).catch(() => {});
      }
    })();
```

- [ ] **Step 4: Add `reapplyBlocks`**

In `src/firewall.ts`, add after `unblockIP` (before `getBlockedIPsOrNull`):

```ts
// Re-add every given IP to the pf table under a single sudo prompt — used
// after a reboot wiped the kernel ruleset. Best-effort per IP; collects
// failures. Marks successfully-applied IPs with the current boot id so the
// stale banner clears. Does NOT record new history events (these are not new
// blocks, just re-enforcement of existing ones).
export async function reapplyBlocks(
  ips: string[],
  password: string,
): Promise<{ success: boolean; applied: string[]; failed: { ip: string; message: string }[]; message?: string }> {
  if (typeof password !== 'string' || password.length === 0) {
    return { success: false, applied: [], failed: [], message: 'sudo password required' };
  }

  try {
    await validateSudo(password);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, applied: [], failed: [], message: msg };
  }

  try {
    await ensureAnchor();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, applied: [], failed: ips.map((ip) => ({ ip, message: msg })), message: msg };
  }

  const currentBoot = await getBootId();
  const applied: string[] = [];
  const failed: { ip: string; message: string }[] = [];
  for (const ip of ips) {
    if (!isBlockableIP(ip)) {
      failed.push({ ip, message: 'non-blockable IP' });
      continue;
    }
    try {
      await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'add', ip], { timeout: 5000 });
      applied.push(ip);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      failed.push({ ip, message: msg });
    }
  }

  if (currentBoot != null && applied.length > 0) {
    await markReapplied(applied, currentBoot);
  }
  return { success: failed.length === 0, applied, failed };
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pnpm test 2>&1 | grep -A2 firewall`
Expected: PASS — the empty-password test passes (no sudo spawned).

- [ ] **Step 6: Typecheck**

Run: `pnpm typecheck`
Expected: no output, exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/firewall.ts src/firewall.test.ts
git commit -m "feat(firewall): stamp appliedBoot on block; add reapplyBlocks batch re-apply"
```

---

## Task 4: `routes.ts` — expose stale state + `POST /api/reapply`

**Files:**
- Modify: `src/routes.ts` (imports; `/api/block-history` at lines 199-208; add `/api/reapply`)

**Interfaces:**
- Consumes: `getBootId` (Task 1); `countStaleBlocks`, `getBlockHistory` (Task 2); `reapplyBlocks` (Task 3).
- Produces: `GET /api/block-history` → `{ active, history, stale: boolean, staleCount: number }`; `POST /api/reapply` body `{ password }` → `{ success, applied, failed, message? }`.

- [ ] **Step 1: Update imports**

In `src/routes.ts`, extend the three relevant import lines (12-14 area):

```ts
import { blockIP, unblockIP, getBlockedIPsOrNull, reapplyBlocks } from './firewall.js';
import { getBlockHistory, deleteBlockHistoryRow, countStaleBlocks } from './block-store.js';
import { getBootId } from './boot-info.js';
```

- [ ] **Step 2: Add stale fields to `/api/block-history`**

Replace the `/api/block-history` handler (lines 199-208) with:

```ts
router.get('/api/block-history', async (_req, res) => {
  // Pure read — no reconciliation. Reconciling against a live pfctl snapshot on
  // every poll was unsafe: after a reboot pfctl reports the table as gone (an
  // authoritative empty list), which fabricated bulk "unblock" events and
  // deleted still-wanted records; it also raced in-flight unblocks into
  // duplicate history rows and double-spawned pfctl per refresh. block/unblock
  // remain the authoritative mutators of the persisted store.
  //
  // `stale`/`staleCount` flag persisted-active blocks whose appliedBoot differs
  // from the current boot (almost certainly wiped by a reboot). currentBoot is
  // read without sudo; if it's unreadable we report 0 (no false-alarm banner).
  const data = await getBlockHistory();
  const currentBoot = await getBootId();
  const staleCount = currentBoot == null ? 0 : countStaleBlocks(data.active, currentBoot);
  res.json({ ...data, stale: staleCount > 0, staleCount });
});
```

- [ ] **Step 3: Add `POST /api/reapply`**

In `src/routes.ts`, add directly after the `/api/unblock/:ip` handler (after line 140):

```ts
router.post('/api/reapply', async (req, res) => {
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const ips = (await getBlockHistory()).active.map((r) => r.ip);
  const result = await reapplyBlocks(ips, password);
  res.status(result.success ? 200 : 400).json(result);
});
```

- [ ] **Step 4: Typecheck**

Run: `pnpm typecheck`
Expected: no output, exit 0.

- [ ] **Step 5: Run the existing suite (no regressions)**

Run: `pnpm test 2>&1 | tail -8`
Expected: all tests pass (no new unit tests in this task; routes are integration-verified next).

- [ ] **Step 6: Runtime smoke (routes have no unit harness in this project)**

Start the server (`pnpm dev`), then in another shell verify the contract:

```bash
# stale fields present on block-history
curl -s -H 'x-requested-by: netwatcher' http://127.0.0.1:3847/api/block-history | python3 -c 'import sys,json; d=json.load(sys.stdin); print("stale" in d, "staleCount" in d)'
# expected: True True

# reapply rejects a missing password (no sudo spawned) -> 400 + password message
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'x-requested-by: netwatcher' -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:3847/api/reapply
# expected: 400
```

- [ ] **Step 7: Commit**

```bash
git add src/routes.ts
git commit -m "feat(firewall): expose stale block state on /api/block-history; add POST /api/reapply"
```

---

## Task 5: Frontend — stale banner + one-click re-apply

**Files:**
- Modify: `public/js/state.js:5-22` (S fields)
- Modify: `public/js/api.js` (`fetchBlockedIPs` stale parse; add `reapplyBlocks`)
- Modify: `public/js/modals.js:175-206` (`renderBlockedPanel` banner)
- Modify: `public/js/actions.js` (delegated handler in `initActions`; add `reapplyBlocksAction`)
- Modify: `public/style.css` (banner styles, append)

**Interfaces:**
- Consumes: `POST /api/reapply` + `GET /api/block-history` stale fields (Task 4); existing `askSudoPassword`, `lockBtn`, `showToast`, `sendFirewallRequest`, `fetchBlockedIPs`, `S`, `el`.
- Produces: UI behavior only (no exported contract other modules consume).

- [ ] **Step 1: Add state fields**

In `public/js/state.js`, add two fields inside the `S` object (e.g. after `blockedMeta` on line 9):

```js
  blocksStale:      false,
  staleCount:       0,
```

- [ ] **Step 2: Parse stale fields + add the `reapplyBlocks` fetcher**

In `public/js/api.js`, inside `fetchBlockedIPs`, after the `for (const rec of (data.active || [])) { … }` loop (currently ends at line 121) and still inside that `try`, add:

```js
    S.blocksStale = !!data.stale;
    S.staleCount = data.staleCount || 0;
```

Then add a new exported fetcher at the end of `public/js/api.js` (after `sendFirewallRequest`):

```js
// Re-apply all persisted blocks to pf in one request. `sendFirewallRequest`
// already POSTs { password } and zeroes it after send; the ip arg is unused
// by that helper (the path carries no ip here).
export function reapplyBlocks(password) {
  return sendFirewallRequest('/api/reapply', '', password);
}
```

- [ ] **Step 3: Render the banner in `renderBlockedPanel`**

In `public/js/modals.js`, replace `renderBlockedPanel` (lines 175-206) so a stale banner is prepended in both the empty and populated branches:

```js
export function renderBlockedPanel() {
  const { blockedListEl } = el;
  const banner = S.blocksStale
    ? `<div class="blocked-stale-banner" role="alert">⚠️ ${S.staleCount} blocked IP${S.staleCount === 1 ? '' : 's'} ${S.staleCount === 1 ? 'is' : 'are'} not currently enforced (likely after a reboot). <button class="blocked-reapply-btn" data-action="reapply-blocks">Re-apply all</button></div>`
    : '';
  const ips = [...S.blockedIPs];
  const q = S.blockedQ.toLowerCase();
  const filtered = ips.filter(ip => {
    const meta = S.blockedMeta.get(ip);
    const hay = `${ip} ${meta?.country || ''} ${meta?.isp || ''}`.toLowerCase();
    return !q || hay.includes(q);
  });
  if (filtered.length === 0) {
    blockedListEl.innerHTML = banner + `<div class="blocked-empty">${q ? `No blocked addresses match "${escapeHtml(q)}"` : 'No IPs currently blocked'}</div>`;
    return;
  }
  blockedListEl.innerHTML = banner + filtered.map(ip => {
    const meta = S.blockedMeta.get(ip) || {};
    const country = meta.country || '';
    const cc = meta.countryCode || '';
    const isp = meta.isp || '';
    const f = flag(cc);
    const when = meta.blockedAt ? relTime(meta.blockedAt) : '—';
    const ccLabel = f ? `${f} ${escapeHtml(country)}` : escapeHtml(country || '—');
    return `
      <div class="blocked-row" data-ip="${escapeHtml(ip)}">
        <span class="ip">${escapeHtml(ip)}</span>
        <span class="cc">${ccLabel}</span>
        <span class="isp" title="${escapeHtml(isp)}">${escapeHtml(isp)}</span>
        <span class="when">${escapeHtml(when)}</span>
        <button class="un" data-action="unblock" data-ip="${escapeHtml(ip)}">Unblock</button>
      </div>
    `;
  }).join('');
}
```

(`S.staleCount` is a number, safe to interpolate without escaping.)

- [ ] **Step 4: Handle the re-apply click + add `reapplyBlocksAction`**

In `public/js/actions.js`, update the import from `./api.js` (line 8) to include `reapplyBlocks`:

```js
import { apiFetch, sendFirewallRequest, fetchBlockedIPs, fetchConnections, reapplyBlocks } from './api.js';
```

Add the action function (e.g. after `unblockIPAction`, near line 61):

```js
// ---------- Re-apply all blocks (post-reboot) ----------
export function reapplyBlocksAction(btn) {
  const unlock = lockBtn(btn);
  const ips = [...S.blockedMeta.keys()];
  const target = ips.length === 1 ? ips[0] : `${ips.length} blocked IPs`;
  askSudoPassword('Re-apply', target, async (password) => {
    if (!password) { unlock(); return; }
    try {
      const result = await reapplyBlocks(password);
      password = '';
      const n = result.applied ? result.applied.length : 0;
      const f = result.failed ? result.failed.length : 0;
      const msg = result.success
        ? `Re-applied ${n} IP${n === 1 ? '' : 's'}`
        : (result.message || `Re-applied ${n}, ${f} failed`);
      showToast(msg, result.success ? 'success' : 'error');
      await fetchBlockedIPs();
    } catch (err) {
      showToast('Failed to re-apply: ' + err.message, 'error');
    } finally {
      unlock();
    }
  });
}
```

In `initActions`, extend the delegated click listener on `blockedListEl` (lines 394-398) to catch the banner button first:

```js
  blockedListEl.addEventListener('click', (e) => {
    const reapply = e.target.closest('[data-action="reapply-blocks"]');
    if (reapply) { reapplyBlocksAction(reapply); return; }
    const b = e.target.closest('[data-action="unblock"]');
    if (!b) return;
    unblockIPAction(b.dataset.ip, b);
  });
```

- [ ] **Step 5: Add banner styles**

Append to `public/style.css`:

```css
/* Stale-blocks banner (re-apply after reboot) */
.blocked-stale-banner {
  margin: 0 0 8px;
  padding: 8px 10px;
  border: 1px solid rgba(240, 170, 70, 0.5);
  border-radius: 6px;
  background: rgba(240, 170, 70, 0.12);
  color: #f0aa46;
  font-size: 12px;
  line-height: 1.4;
}
.blocked-reapply-btn {
  margin-left: 6px;
  padding: 3px 8px;
  border: 1px solid currentColor;
  border-radius: 4px;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font: inherit;
  font-weight: 600;
}
.blocked-reapply-btn:hover { background: rgba(240, 170, 70, 0.2); }
```

- [ ] **Step 6: Typecheck + existing suite**

Run: `pnpm typecheck && pnpm test 2>&1 | tail -8`
Expected: typecheck clean; all tests pass (no new unit tests — frontend DOM behavior is runtime-verified per the project's testing posture).

- [ ] **Step 7: Runtime verification (browser)**

With `pnpm dev` running, in the browser (or via the verify skill / Chrome DevTools):
1. Block any IP, confirm it appears in the blocked panel and `data/blocks.json` shows that record with a numeric `appliedBoot`.
2. Simulate post-reboot drift: stop the server, edit `data/blocks.json` to set that record's `appliedBoot` to a different number (e.g. `1`), restart `pnpm dev`, reload the page.
3. Expected: the blocked panel shows the amber banner "⚠️ 1 blocked IP is not currently enforced …" with a **Re-apply all** button.
4. Click **Re-apply all** → sudo modal → enter password → toast "Re-applied 1 IP"; the banner disappears on the next blocked refresh; `data/blocks.json`'s `appliedBoot` now matches the current boot.

- [ ] **Step 8: Commit**

```bash
git add public/js/state.js public/js/api.js public/js/modals.js public/js/actions.js public/style.css
git commit -m "feat(ui): stale-blocks banner + one-click re-apply after reboot"
```

---

## Self-Review

**1. Spec coverage**

- Detect via boot time without sudo → Task 1 (`boot-info`) + Task 2 (`countStaleBlocks`) + Task 4 (`/api/block-history` wiring). ✅
- Per-IP `appliedBoot` marker (chosen over single store-wide marker) → Task 2 (`BlockRecord.appliedBoot`, `recordBlock` param), Task 3 (`blockIP` stamp + `reapplyBlocks` mark). ✅
- Warn via additive `stale`/`staleCount` on `/api/block-history`; `/api/blocked` unchanged → Task 4. ✅
- Frontend banner + reuse of existing sudo modal & in-flight lock → Task 5. ✅
- `POST /api/reapply` (CSRF via the global `/api` middleware, password in body, argv-form pfctl, best-effort with per-IP failures, no new history events) → Task 3 + Task 4. ✅
- Edge cases: `getBootId` null → staleCount 0 (Task 4); partial failure keeps stale (Task 3 returns `failed`, marks only `applied`); empty active → no banner (countStaleBlocks 0); legacy `appliedBoot` undefined → stale (Task 2 test asserts this). ✅
- Out of scope (manual `pfctl -F`, inverse drift, boot auto-apply) → not in any task. ✅
- Testing posture (pure fns + FS-isolated store; pfctl/routes/DOM integration) → Tasks 1-3 unit tests; Tasks 4-5 runtime-verified. ✅

**2. Placeholder scan**: No TBD/TODO/"handle errors"/"similar to". Every code step shows complete code; every test step shows full assertions; every command states expected output. ✅

**3. Type consistency**:
- `reapplyBlocks(ips: string[], password: string)` — same signature in Task 3 (definition), Task 4 (call). ✅
- Return shape `{ success, applied, failed: {ip,message}[], message? }` — identical across Task 3, Task 4 response, Task 5 consumption (`result.applied`, `result.failed`, `result.message`). ✅
- `recordBlock(ip, meta, appliedBoot?)` — Task 2 default `null`; Task 3 passes `bootId`. ✅
- `markReapplied(ips, bootId)` / `countStaleBlocks(active, currentBoot)` — defined Task 2, used Task 3/Task 4 with matching arg types. ✅
- Frontend `S.blocksStale`/`S.staleCount` — defined Task 1 (state.js), set Task 2 (api.js parse), read Task 3 (modals.js banner). ✅
- `data-action="reapply-blocks"` — emitted in `renderBlockedPanel` (Task 5 Step 3), matched in `initActions` (Task 5 Step 4). ✅
