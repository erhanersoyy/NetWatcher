# NetWatcher Phase 2 — `app.js` → ES Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Execute in an isolated git worktree** (superpowers:using-git-worktrees) — this restructures the whole frontend.

**Goal:** Split the 1887-line `public/app.js` (one classic `<script>`) into ~10 focused ES modules under `public/js/`, wired by a tiny `EventTarget` bus, with **zero behavior change** — no framework, no bundler.

**Architecture:** Leaf-first mechanical extraction. First move `app.js` verbatim into `public/js/main.js` behind `<script type="module">` (behavior-identical), then extract leaves (util, dom, state+bus) and feature modules one at a time, re-verifying after every task. The only structural change is decoupling the ~8 cross-module `renderQueue()` / fetch→render call sites through a `bus` (`emit('data:changed')` / `on(...)`) so `api.js` and `sse.js` don't import the render modules (avoids circular imports).

**Tech Stack:** Vanilla JS ES modules (native `import`/`export`, no bundler), served as static files; Node's built-in test runner (`node:test`) for the now-isolable pure helpers; `tsx` only for the backend (unchanged).

## Global Constraints

- **No framework, no bundler, no signals library, no new runtime deps.** Native ESM + ONE `EventTarget` bus is the whole architecture. (User rule: prefer the 50-line solution.)
- **Zero behavior change.** Every task must leave the app working identically — verified by `node --check` on each module + a manual browser pass (or the verification script in the Final Verification section).
- **macOS only; no build step.** `public/js/*.js` are served raw. `index.html` loads only `js/main.js` as `type="module"`; the browser resolves the import graph.
- **`window.topojson` must stay accessible** — the topojson-client `<script>` (SRI-pinned `@3.1.0`) loads before the module and populates `window.topojson`; `radar.js` reads it via `window.topojson` (do NOT try to `import` it — that needs a bundler).
- **Relative imports use explicit `.js` extensions** (native ESM requires them): `import { escapeHtml } from './util.js'`.
- **Run `node --check public/js/<file>.js` after each file edit**, and `pnpm test` after util extraction. Conventional commits; commit after each task. Project docs/comments in English.

## File Structure (target `public/js/`)

| File | Responsibility | Source (current `app.js`) |
|---|---|---|
| `util.js` | Pure helpers, no DOM/state | escapeHtml, isIPv6, isLocalhost, isPrivateIP, flag, formatBytes, fmtBytes, relTime, formatTime, looksLikeIP |
| `dom.js` | All `getElementById` handles, exported as a frozen `el` object | the ~56 handles at lines 5–59 |
| `state.js` | Shared mutable state + the `EventTarget` bus (`bus`, `emit`, `on`) | the state vars at lines 62–83, 212, 858, etc. + new bus |
| `api.js` | `apiFetch` + endpoint fetchers; update state, `emit` events (no direct render calls) | apiFetch, fetchConnections, fetchHostInfo, fetchBlockedIPs, sendFirewallRequest |
| `connection-list.js` | Queue render + filters + queue events; `on('data:changed', renderQueue)` | renderQueue, renderProcRow, renderConnBlock, applyFilters, sortProcesses, procSummary, computeRenderSig, flashNewRows, hiddenCounts, updateChipCounts, renderQueueEmpty, renderTopTalkers, updateExpandToggle, clearFilters + queue/search/sort/chips handlers |
| `radar.js` | Canvas radar (self-contained) + observers + country-rings loader; `on('data:changed', …)` + `on('host:changed', radarSetHome)` | all radar fns (lines ~1434–1660) |
| `panels.js` | Throughput graph, system-health, clock, tweaks, masthead host-info render | pushThroughput, drawGraph, refreshSystemHealth, tickClock, applyTweaks, masthead update + system-health interval |
| `modals.js` | Toast, focus-trap, all dialogs, blocked-list modal + blocked sidebar render | showToast, trapFocus, showConfirmDialog, askSudoPassword, showVtModal, formatVtOutput, showBlockedListModal, renderBlockedListBody, wireBlockedToolbar, buildBlockedRows, renderBlockedPanel |
| `actions.js` | Privileged client actions (open modal → call api) | lockBtn, blockIPAction, unblockIPAction, blockIPManualAction, unblockBulkAction, killProcessAction, doKill, vtCheckAction, killsInFlight |
| `sse.js` | `connectTrafficStream` + idle decay; patches rows in place, `emit` on health change | connectTrafficStream |
| `main.js` | Entry: import all, `refreshAll`/`scheduleRefresh`, global keydown, init/bootstrap | refreshAll, scheduleRefresh, the bottom init block + global listeners |
| `util.test.js` | `node:test` unit tests for the now-pure util helpers | new |

> **The one design decision — the `bus`.** `renderQueue()` is called from 8 sites across future module boundaries, and `api.js`/`sse.js` must trigger re-renders without importing `connection-list.js` (which would import `api.js` back → circular). Fix with a ~12-line `EventTarget` in `state.js`: producers `emit('data:changed')`; consumers `on('data:changed', renderQueue)`. **No framework, no store library** — one `EventTarget` is the entire pattern.

**Out of scope (do NOT do here):** changing any behavior, restyling, new features, touching `src/` (backend), or merging the two backend address parsers / IP validators (explicitly left alone per the analysis).

---

### Task 1: Make `app.js` a module (verbatim move) — behavior-identical baseline

The safest first step: relocate the file into `public/js/main.js` unchanged and load it as a module. Top-level `let/const`/functions become module-scoped (still all in one scope → hoisting + cross-references work exactly as before). Nothing is assigned to `window`, and `window.topojson` is still read globally, so behavior is identical.

**Files:**
- Create: `public/js/main.js` (the entire current `public/app.js`, byte-for-byte)
- Delete: `public/app.js`
- Modify: `public/index.html:254`

- [ ] **Step 1: Move the file**

```bash
mkdir -p public/js
git mv public/app.js public/js/main.js
```

- [ ] **Step 2: Point index.html at the module**

In `public/index.html`, change line 254 from:
```html
<script src="app.js"></script>
```
to:
```html
<script type="module" src="js/main.js"></script>
```

- [ ] **Step 3: Syntax check**

Run: `node --check public/js/main.js`
Expected: exit 0, no output.

- [ ] **Step 4: Manual verification (browser)**

Run `pnpm dev`, load `http://localhost:3847`. Confirm **identical** behavior: connection list renders + live-updates, radar animates, throughput graphs, blocked panel, expand a row, open a modal, no new console errors. (A `type="module"` script is deferred + strict-mode; verify nothing relied on sloppy-mode or sync-script timing — it shouldn't, since all work happens in the init block at the bottom.)

- [ ] **Step 5: Commit**

```bash
git add public/index.html public/js/main.js
git commit -m "refactor(ui): move app.js to js/main.js as an ES module (no behavior change)"
```

---

### Task 2: Extract `util.js` (pure helpers) + unit tests

These functions have no DOM/state dependencies → the first cleanly-testable unit.

**Files:**
- Create: `public/js/util.js`
- Create: `public/js/util.test.js`
- Modify: `public/js/main.js` (remove the moved fns; add `import`)
- Modify: `package.json` (test glob already covers `src/**`; add `public/**` — see Step 5)

**Interfaces:**
- Produces: `export function escapeHtml(s), isIPv6(a), isLocalhost(a), isPrivateIP(ip), flag(cc), formatBytes(n), fmtBytes(n), relTime(ts), formatTime(ts), looksLikeIP(s)` — signatures unchanged from current `app.js`.

- [ ] **Step 1: Create `public/js/util.js`**

Move these functions verbatim from `main.js` into `util.js` (current lines: `escapeHtml` 99, `isIPv6` 106, `isLocalhost` 107, `isPrivateIP` 108, `flag` 128, `formatBytes` 132, `relTime` 744, `formatTime` 1346, `looksLikeIP` 1228, `fmtBytes` 1790), prefixing each with `export`. Keep bodies identical. `escapeHtml`'s cached lookup table moves with it.

- [ ] **Step 2: Write the failing test** — `public/js/util.test.js`

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, isPrivateIP, formatBytes, looksLikeIP, isIPv6 } from './util.js';

test('escapeHtml neutralizes HTML', () => {
  assert.equal(escapeHtml('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
});
test('isPrivateIP classifies RFC1918 + link-local', () => {
  assert.equal(isPrivateIP('192.168.1.1'), true);
  assert.equal(isPrivateIP('10.0.0.1'), true);
  assert.equal(isPrivateIP('169.254.1.1'), true);
  assert.equal(isPrivateIP('8.8.8.8'), false);
});
test('formatBytes scales units', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.match(formatBytes(1536), /1\.5 KB/);
});
test('looksLikeIP validates v4/v6', () => {
  assert.equal(looksLikeIP('1.2.3.4'), true);
  assert.equal(looksLikeIP('not-an-ip'), false);
});
test('isIPv6 detects colons', () => {
  assert.equal(isIPv6('::1'), true);
  assert.equal(isIPv6('1.2.3.4'), false);
});
```

(Adjust the exact expected strings in Step 4 to match the real implementations — read each function and assert its actual output.)

- [ ] **Step 3: Run to verify it fails**

Run: `node --import tsx --test public/js/util.test.js`
Expected: FAIL — `Cannot find module './util.js'` until Step 1 is saved; once saved, fix any assertion that mismatches the real output.

- [ ] **Step 4: Wire the import in `main.js`**

At the top of `main.js`, add:
```js
import { escapeHtml, isIPv6, isLocalhost, isPrivateIP, flag, formatBytes, fmtBytes, relTime, formatTime, looksLikeIP } from './util.js';
```
Delete the now-moved function declarations from `main.js`.

- [ ] **Step 5: Extend the test script to cover `public/`**

In `package.json`, change the `test` script to also run `public/**/*.test.js`:
```json
    "test": "node --import tsx --test 'src/**/*.test.ts' 'public/**/*.test.js'"
```

- [ ] **Step 6: Verify**

Run: `node --check public/js/main.js && pnpm test`
Expected: util tests pass; backend tests still pass. Then `pnpm dev` + browser: app still works (escaping, byte formatting, flags, relative times all render).

- [ ] **Step 7: Commit**

```bash
git add public/js/util.js public/js/util.test.js public/js/main.js package.json
git commit -m "refactor(ui): extract pure helpers into util.js (+ node:test unit tests)"
```

---

### Task 3: Extract `dom.js` (element handles)

**Files:**
- Create: `public/js/dom.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Produces: `export const el = Object.freeze({ queueEl, qEl, sortSelect, … })` — one frozen object holding all ~56 `getElementById` results. Consumers read `el.queueEl` etc.

- [ ] **Step 1: Create `public/js/dom.js`**

Move every top-level `const X = document.getElementById('…')` (lines 5–59) into `dom.js` as one exported frozen object:
```js
const $ = (id) => document.getElementById(id);
export const el = Object.freeze({
  queueEl: $('queue'), qEl: $('searchInput'), sortSelect: $('sortSelect'), chipsEl: $('chips'),
  // …every handle, keyed by its current variable name → its id…
  hostISP: $('hostISP'), queueISP: $('queueISP'), queueGeo: $('queueGeo'),
});
```
Read lines 5–59 of `main.js` for the exact id of each handle. (Module load order: `main.js` imports `dom.js`; since `index.html` runs `js/main.js` as a deferred module AFTER the DOM is parsed, `getElementById` resolves correctly.)

- [ ] **Step 2: Rewrite references in `main.js`**

This task touches MANY call sites. Easiest mechanical approach: keep the short names by destructuring at the top of `main.js` after the import:
```js
import { el } from './dom.js';
const { queueEl, qEl, sortSelect, chipsEl, blockedCountEl, statusText, /* …all… */ } = el;
```
This preserves every existing reference (`queueEl`, `statusText`, …) with zero body changes, and later modules can `import { el }` and destructure the handful they use. Delete the original `getElementById` lines from `main.js`.

- [ ] **Step 3: Verify**

Run: `node --check public/js/dom.js && node --check public/js/main.js`
Then `pnpm dev` + browser: every panel still populates (masthead, queue, blocked, health) — a missing/renamed handle would throw at load.

- [ ] **Step 4: Commit**

```bash
git add public/js/dom.js public/js/main.js
git commit -m "refactor(ui): extract DOM handles into dom.js (frozen el object)"
```

---

### Task 4: Extract `state.js` (shared state + the `EventTarget` bus)

**Files:**
- Create: `public/js/state.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Produces:
  - The bus: `export const bus = new EventTarget(); export const emit = (name, detail) => bus.dispatchEvent(new CustomEvent(name, { detail })); export const on = (name, fn) => bus.addEventListener(name, (e) => fn(e.detail));`
  - Mutable state as a single mutable object so cross-module writes are visible: `export const S = { lastData: null, hostInfo: null, blockedIPs: new Set(), blockedMeta: new Map(), liveTraffic: new Map(), streamHealthy: false, lastDeltaAt: 0, filter: { sys:true, v6:true, priv:true, q:'' }, blockedQ:'', expandedPids: new Set(), prevPids: null, prevConnKeys: null, lastRenderSig:'', killsInFlight: new Set(), refreshTimer: null, refreshIntervalMs: 300000, … }`.
  - `export const CSRF_HEADER = { 'x-requested-by': 'netwatcher' };`

> **Why a single `S` object, not 26 exported `let`s:** ES module live-bindings are read-only to importers — a consumer can't reassign an imported `let`. Writers (`fetchConnections` setting `lastData`) must mutate a shared object's property (`S.lastData = data`). Radar's geometry (`RW/CX/RR/sweepAngle/...`) is radar-internal → keep it module-local in `radar.js`, NOT in `S`. Only put genuinely cross-module state in `S`.

- [ ] **Step 1: Create `public/js/state.js`** with the bus, `S`, and `CSRF_HEADER` as above. Initialize each `S.*` to the current default from `main.js` (lines 62–83 etc.).

- [ ] **Step 2: Migrate references in `main.js`**

Replace bare state identifiers with `S.` access. To minimize churn in this single-file-still stage, add after the import:
```js
import { S, bus, emit, on, CSRF_HEADER } from './state.js';
```
Then either (a) destructure read-mostly values where safe, or (b) sweep `lastData`→`S.lastData`, `blockedIPs`→`S.blockedIPs`, etc. **Do not destructure values that get reassigned** (lastData, prevPids, streamHealthy, lastDeltaAt, lastRenderSig, refreshTimer) — those must stay `S.x` so writes are shared. Sets/Maps (blockedIPs, liveTraffic, expandedPids, killsInFlight, blockedMeta) are mutated in place, so a `const blockedIPs = S.blockedIPs` alias is safe for reads/mutations but NOT if any code does `blockedIPs = new Set(...)` (fetchBlockedIPs does) → keep those as `S.blockedIPs`.

- [ ] **Step 3: Verify**

Run: `node --check public/js/state.js && node --check public/js/main.js`; `pnpm dev` + browser: full pass (filters, blocking, live traffic, flash) — state reads/writes must behave exactly as before.

- [ ] **Step 4: Commit**

```bash
git add public/js/state.js public/js/main.js
git commit -m "refactor(ui): extract shared state + EventTarget bus into state.js"
```

---

### Task 5: Extract `api.js` and decouple render via the bus

**Files:**
- Create: `public/js/api.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Consumes: `S`, `emit` (state.js); `el` (dom.js) for the few status writes; `escapeHtml` etc. only if needed.
- Produces: `export async function fetchConnections(), fetchHostInfo(opts), fetchBlockedIPs(), sendFirewallRequest(path, ip, password); export function apiFetch(url, options)`.

- [ ] **Step 1: Create `public/js/api.js`** — move `apiFetch` (90), `fetchConnections` (624), `fetchHostInfo` (603), `fetchBlockedIPs` (669), `sendFirewallRequest` (789). Replace their direct render calls with bus emits:
  - In `fetchConnections`: after `S.lastData = data; …`, replace `renderQueue()` with `emit('data:changed')`. Keep the inline error/banner handling (it touches `el.queueEl` directly — that's fine, import `el`). Keep the `liveTraffic` prune.
  - In `fetchHostInfo`: after setting `S.hostInfo` + masthead text, replace the direct `radarSetHome(...)` call with `emit('host:changed', { lat, lon })`. (Masthead DOM writes can stay here or move to panels in Task 7; for now keep them, importing `el`.)
  - In `fetchBlockedIPs`: replace `renderBlockedPanel()` + `renderQueue()` with `emit('blocked:changed')` and `emit('data:changed')`.

- [ ] **Step 2: Wire in `main.js`** — `import { fetchConnections, fetchHostInfo, fetchBlockedIPs, sendFirewallRequest, apiFetch } from './api.js';` and delete the moved fns. The render functions still living in `main.js` get subscribed to the bus in their eventual home modules (Tasks 6/7/8/10); for THIS task, add temporary subscriptions near the bottom of `main.js` so behavior holds:
```js
on('data:changed', () => renderQueue());
on('blocked:changed', () => renderBlockedPanel());
on('host:changed', ({ lat, lon }) => radarSetHome(lat, lon));
```
(These move into their modules as those are extracted; the bus makes that a no-op change.)

- [ ] **Step 3: Verify**

Run: `node --check public/js/api.js && node --check public/js/main.js`; `pnpm dev` + browser: poll still re-renders the queue, host-info still sets the radar home + masthead, a block/unblock still refreshes the panel. Confirm the inline-error/Retry + stale-refresh banner still work (force a fetch failure).

- [ ] **Step 4: Commit**

```bash
git add public/js/api.js public/js/main.js
git commit -m "refactor(ui): extract api.js; route fetch→render through the bus"
```

---

### Task 6: Extract `radar.js`

Radar is the most self-contained subsystem (the map confirms `radarFrame` touches no other module). Its geometry state stays module-local.

**Files:**
- Create: `public/js/radar.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Consumes: `S` (reads `S.lastData`/`S.liveTraffic` in `radarUpdateTargets`), `on` (state.js), `el` (the `#radar` canvas), `formatBytes`/`flag` (util) as used.
- Produces: `export function initRadar()` — sets up the canvas, observers, country-rings loader, and `on('data:changed', () => radarUpdateTargets(currentSorted))` + `on('host:changed', ({lat,lon}) => radarSetHome(lat,lon))`. Optionally `export { radarSetHome }` if any caller still needs it directly (it shouldn't after the bus).

- [ ] **Step 1: Create `public/js/radar.js`** — move all radar code: state (lines 1434–1449, 1545–1546), `scheduleRadarFrame`, `motionQuery` + its change listener, `visibilitychange` handler (radar part only — the poll-skip part stays in panels/main), `sizeRadar`, `layoutBearings`, `project`, `reprojectCountryBorders`, `drawCountryBorders`, `reprojectTargets`, `radarSetHome`, `radarUpdateTargets`, `radarFrame`, the `window.resize` handler, the `ResizeObserver` IIFE, and the country-rings loader IIFE (keeps reading `window.topojson`). Wrap the top-level setup (observers, initial `sizeRadar()`, first `scheduleRadarFrame()`) into an exported `initRadar()` so `main.js` controls start order.
- **Bus wiring:** `radarUpdateTargets` currently takes `sorted` from `renderQueue`. Since radar now reacts to `data:changed` independently, have it derive its targets from `S.lastData` (apply the same filtering or accept the sorted list via the event detail). Simplest: `emit('data:changed', { sorted })` from `connection-list` later; for now, in `initRadar`, `on('data:changed', (d) => { radarUpdateTargets(d?.sorted ?? applyVisible()); scheduleRadarFrame(); })`. Keep `motionQuery` here (radar owns it); `flashNewRows` in connection-list needs reduced-motion too → export a tiny `prefersReducedMotion()` from a shared spot (util or state) OR have connection-list create its own `matchMedia`. Put `export const prefersReducedMotion = () => !!motionQuery?.matches;` in radar.js and import it in connection-list.

- [ ] **Step 2: Wire in `main.js`** — `import { initRadar } from './radar.js';`, delete moved code, call `initRadar()` in the init block. Remove the temporary `on('host:changed', …)` shim (now owned by radar).

- [ ] **Step 3: Verify**

Run: `node --check public/js/radar.js && node --check public/js/main.js`; `pnpm dev` + browser: radar sweeps, country borders draw, pins update on new connections, reduced-motion still freezes the sweep, resize/visibility gating still works.

- [ ] **Step 4: Commit**

```bash
git add public/js/radar.js public/js/main.js
git commit -m "refactor(ui): extract self-contained radar.js (bus-driven target updates)"
```

---

### Task 7: Extract `panels.js`

**Files:**
- Create: `public/js/panels.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Consumes: `el`, `S`, `on`, `formatBytes`/`fmtBytes` (util), `apiFetch` (api — for system-health) or move the health fetch into api.js. Decide: keep `refreshSystemHealth`'s fetch in panels using `apiFetch` (import it).
- Produces: `export function pushThroughput(rx, tx), initPanels()` (clock interval, system-health interval, tweaks handlers, applyTweaks). `pushThroughput` is imported by `sse.js`.

- [ ] **Step 1: Create `public/js/panels.js`** — move `pushThroughput` (1414), `drawGraph` (1423), `refreshSystemHealth` (1795), `tickClock` (592), `applyTweaks` (1832), `fmtBytes` if not already in util (it is — import it), the masthead host-info DOM updates if you moved them out of `fetchHostInfo` (optional; otherwise leave in api). Wrap the clock `setInterval`, system-health `setInterval` (+ its `visibilitychange` skip), and the tweaks click handlers into `initPanels()`.

- [ ] **Step 2: Wire in `main.js`** — `import { pushThroughput, initPanels } from './panels.js';`, delete moved code, call `initPanels()` in init.

- [ ] **Step 3: Verify**

Run: `node --check public/js/panels.js && node --check public/js/main.js`; `pnpm dev` + browser: throughput graphs update, system-health bars update, clock ticks, density + radar tweaks toggles work.

- [ ] **Step 4: Commit**

```bash
git add public/js/panels.js public/js/main.js
git commit -m "refactor(ui): extract panels.js (throughput, system-health, clock, tweaks)"
```

---

### Task 8: Extract `modals.js`

**Files:**
- Create: `public/js/modals.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Consumes: `el`, `S`, `escapeHtml`/`looksLikeIP`/`relTime`/`flag`/`formatBytes` (util), `apiFetch` (api), and `actions.js` for the per-row block/unblock callbacks (Task 9) — to avoid a modals↔actions cycle, have the blocked-list modal `emit` action requests or import the specific action fns (actions.js should NOT import modals for the dialogs it opens — see Task 9 note).
- Produces: `export function showToast(msg, type), trapFocus(overlay), showConfirmDialog(message, onConfirm, onCancel, confirmLabel), askSudoPassword(action, target, onSubmit), showVtModal(ip, content, success), showBlockedListModal(), renderBlockedPanel()`.

- [ ] **Step 1: Create `public/js/modals.js`** — move `showToast` (890), `trapFocus` (902), `showConfirmDialog` (920), `askSudoPassword` (953), `showVtModal` (1008), `formatVtOutput` (1036), `showBlockedListModal` (1063), `renderBlockedListBody` (1092), `wireBlockedToolbar` (1155), `buildBlockedRows` (1320), `renderBlockedPanel` (712), and the blocked panel search/export/add/history listeners (wrap into an exported `initBlockedPanel()` or include in main's bootstrap). `on('blocked:changed', renderBlockedPanel)`.

> **Cycle caution:** `modals.js` (blocked-list rows, manual-add) needs the firewall actions from `actions.js` (Task 9), and `actions.js` needs `askSudoPassword`/`showConfirmDialog`/`showToast` from `modals.js`. Break the cycle by keeping the **dialog primitives** (`showConfirmDialog`, `askSudoPassword`, `showToast`, `trapFocus`) in `modals.js` and the **action orchestration** (`blockIPAction`, etc.) in `actions.js` that imports those primitives. `modals.js`'s blocked-list rows then import the actions — that's a one-way `modals → actions → modals(primitives)` chain. A one-way chain through distinct exports is fine in ESM as long as it's not a true import cycle at module-eval time; if a cycle warning appears, route the blocked-list row actions through the `bus` (`emit('action:unblock', {ip})`) instead.

- [ ] **Step 2: Wire in `main.js`** — import the modal exports, delete moved code, call `initBlockedPanel()` in init.

- [ ] **Step 3: Verify**

Run: `node --check public/js/modals.js && node --check public/js/main.js`; `pnpm dev` + browser: toast appears, confirm dialog (Esc/focus-trap/restore), sudo dialog, VT modal, blocked-history modal (open/select/bulk), blocked sidebar render + search/export.

- [ ] **Step 4: Commit**

```bash
git add public/js/modals.js public/js/main.js
git commit -m "refactor(ui): extract modals.js (dialogs, focus-trap, blocked panel/history)"
```

---

### Task 9: Extract `actions.js` (privileged client actions) + unify the in-flight lock

**Files:**
- Create: `public/js/actions.js`
- Modify: `public/js/main.js`, `public/js/modals.js` (blocked-list row handlers use `lockBtn`)

**Interfaces:**
- Consumes: `S`, `apiFetch`/`sendFirewallRequest` (api), `showConfirmDialog`/`askSudoPassword`/`showToast` (modals).
- Produces: `export function lockBtn(btn), blockIPAction(ip, btn), unblockIPAction(ip, btn), blockIPManualAction(overlay, opts), unblockBulkAction(ips, overlay), killProcessAction(pid, name, isSystem, btn), vtCheckAction(ip, btn)`.

- [ ] **Step 1: Create `public/js/actions.js`** — move `lockBtn` (783), `blockIPAction` (805), `unblockIPAction` (824), `blockIPManualAction` (1237), `unblockBulkAction` (1293), `killProcessAction` (844), `doKill` (859), `vtCheckAction` (875), and `killsInFlight` (or read it from `S.killsInFlight`).

- [ ] **Step 2: Resolve the deferred Phase 1b cleanup ([762])** — migrate the hand-rolled lock in `modals.js`'s `.blocked-row-remove` handler to `lockBtn`, and add `lockBtn(btn)` to the blocked-history modal's per-row Unblock/Reblock handlers (`renderBlockedListBody`). Now ALL privileged buttons share one lock helper.

- [ ] **Step 3: Wire** — `main.js` imports the actions for the queue click handler (kill/vt/block/unblock delegation, currently in connection-list — Task 10 owns it; until then `main.js` imports actions for that handler). `modals.js` imports `blockIPAction`/`unblockIPAction`/`unblockBulkAction`/`lockBtn` for its rows.

- [ ] **Step 4: Verify**

Run: `node --check public/js/actions.js && node --check public/js/main.js && node --check public/js/modals.js`; `pnpm dev` + browser: kill (user→"Kill Process" confirm, system→"Kill Anyway"), block/unblock (sudo, button locks, no double-submit), VT lookup, bulk unblock, manual add-IP. Per-PID kill guard still holds.

- [ ] **Step 5: Commit**

```bash
git add public/js/actions.js public/js/main.js public/js/modals.js
git commit -m "refactor(ui): extract actions.js; unify in-flight button lock across all privileged buttons"
```

---

### Task 10: Extract `connection-list.js` (the largest consumer)

**Files:**
- Create: `public/js/connection-list.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Consumes: `el`, `S`, `on`/`emit`, util (escapeHtml/formatBytes/flag), `prefersReducedMotion` (radar), `actions.js` (queue click delegation), `procSummary`.
- Produces: `export function initConnectionList()` — registers `on('data:changed', renderQueue)` and the queue `click`/`keydown`, search `input`, `sort` `change`, `chips` `click`, `qToggle` handlers. Internals (`renderQueue`, `renderProcRow`, `renderConnBlock`, `applyFilters`, `sortProcesses`, `procSummary`, `computeRenderSig`, `flashNewRows`, `hiddenCounts`, `updateChipCounts`, `renderQueueEmpty`, `renderTopTalkers`, `updateExpandToggle`, `clearFilters`) are module-private.

- [ ] **Step 1: Create `public/js/connection-list.js`** — move all the functions above (lines 146–175, 195–569 region) and the queue/search/sort/chips/qToggle listeners. Replace the temporary `on('data:changed', () => renderQueue())` shim in `main.js` with the real subscription inside `initConnectionList()`. `radarUpdateTargets` is no longer called directly here — instead `renderQueue` (or the data:changed flow) carries `sorted` to radar via `emit('data:changed', { sorted })`; since api.js already emits `data:changed` on poll, ensure radar derives targets correctly (either from event detail when present or from `S.lastData`).
- The global `document` keydown (`/` focus, `t` tweaks) — `/` belongs to connection-list (focus search), `t` to panels/tweaks; split or keep in `main.js` bootstrap. Keep in `main.js` for simplicity (it's bootstrap-level).

- [ ] **Step 2: Wire in `main.js`** — `import { initConnectionList } from './connection-list.js';`, delete moved code, call `initConnectionList()`.

- [ ] **Step 3: Verify**

Run: `node --check public/js/connection-list.js && node --check public/js/main.js`; `pnpm dev` + browser: full queue behavior — render, expand/collapse (mouse + keyboard + focus restore), filters + chip counts + clear-filters, search, sort, top-talkers, flash on new connection, BLOCKED tags.

- [ ] **Step 4: Commit**

```bash
git add public/js/connection-list.js public/js/main.js
git commit -m "refactor(ui): extract connection-list.js (queue render, filters, events)"
```

---

### Task 11: Extract `sse.js`; reduce `main.js` to bootstrap

**Files:**
- Create: `public/js/sse.js`
- Modify: `public/js/main.js`

**Interfaces:**
- Consumes: `S`, `el`, `emit`, `formatBytes` (util), `pushThroughput` (panels).
- Produces: `export function connectTrafficStream()`.

- [ ] **Step 1: Create `public/js/sse.js`** — move `connectTrafficStream` (1354) + its idle-decay interval. It writes `S.liveTraffic`, sets `S.streamHealthy`/`S.lastDeltaAt`, patches rows in place by `data-traffic-key`, and calls `pushThroughput` (import from panels). On health change it may `emit('stream:health', S.streamHealthy)` (optional; the poll already reads `S.streamHealthy`).

- [ ] **Step 2: Final `main.js`** — it should now contain only: imports of all `init*` functions + `connectTrafficStream` + `refreshAll`/`scheduleRefresh`, the global `document` keydown, the refresh-select/now handlers, and the init block (show "connecting…", `initRadar()/initPanels()/initConnectionList()/initBlockedPanel()`, `connectTrafficStream()`, `refreshAll()`, `scheduleRefresh()`). Confirm `main.js` is now ~40–80 lines.

- [ ] **Step 3: Verify**

Run: `node --check public/js/sse.js && node --check public/js/main.js`; `pnpm dev` + browser: live RX/TX patches rows, throughput graph + idle-decay to 0, stream-offline badge, full app smoke test.

- [ ] **Step 4: Commit**

```bash
git add public/js/sse.js public/js/main.js
git commit -m "refactor(ui): extract sse.js; main.js is now a thin bootstrap"
```

---

### Task 12: Docs + final cleanup

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `CLAUDE.md`** — the Frontend section says "`public/app.js` is a single vanilla JS file." Replace with a short description of the `public/js/` module layout + the `bus` pattern. Update any "No build step — single file" wording to "no build step — native ES modules under `public/js/`, entry `js/main.js`."

- [ ] **Step 2: Verify + commit**

```bash
pnpm typecheck && pnpm test
git add CLAUDE.md
git commit -m "docs: describe the public/js ES-module layout and event bus"
```

---

## Final Verification

After all tasks:

- [ ] `node --check public/js/*.js` — every module parses.
- [ ] `pnpm test` — util + backend tests pass.
- [ ] `pnpm dev` → full manual pass at `http://localhost:3847` with **no console errors**: connection list (render, keyboard expand + focus restore, filters + chip counts + clear, search, sort, flash on new connection), radar (sweep, borders, pins, reduced-motion freeze), throughput + idle-decay, system-health, blocked panel + history modal (open/Esc/focus/bulk), kill (user/system confirm labels), block/unblock (sudo, button locks), VT, manual add-IP, inline error + stale-refresh banner on a forced outage.
- [ ] `git diff main..HEAD -- public/` shows the same runtime behavior with `app.js` replaced by `public/js/*.js`.
- [ ] Per the user's workflow rule: run `/code-review` and `/security-review` before any push.

## Self-Review Notes

- **Spec coverage:** every group in the app.js map → a module (util, dom, state, api, connection-list, radar, panels, modals, actions, sse, main). The report §5.1's module set is covered (dom/state/util/api/connection-list/radar/panels/modals/sse/main) plus an `actions.js` split out of modals for the privileged-action orchestration (cleaner boundary; resolves the Phase 1b [762] lock-duplication note in Task 9).
- **Order rationale:** leaf-first (util → dom → state) so each later module imports already-stable leaves; the bus (Task 4) lands before api (Task 5) so fetch→render decoupling has its mechanism; the biggest consumer (connection-list) and sse come last when all their dependencies exist.
- **Cycle risks flagged:** api↔connection-list (broken by the bus, Task 5), modals↔actions (broken by keeping dialog primitives in modals and orchestration in actions, with a bus fallback noted, Task 8/9).
- **No behavior change is the acceptance test** — every task ends with a browser smoke pass, not just a typecheck.
- **Known approximation:** exact line numbers will drift as functions are removed from `main.js` across tasks; each task names functions by identifier (stable) and gives the original line as a locator. The implementer confirms the symbol before moving it.
