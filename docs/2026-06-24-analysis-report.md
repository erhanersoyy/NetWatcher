# NetWatcher — Analysis Report

*Date: 2026-06-24 · Scope: full audit of `src/` (14 TS modules), `public/app.js` (1589 lines), `public/index.html`, `public/style.css` (775 lines), `package.json`, `CLAUDE.md`.*

---

## 1. Executive Summary

- **NetWatcher is a strong, focused tool with a clean backend and a problematic frontend.** The 14 `src/*.ts` modules are small, single-purpose, and `any`-free; `public/app.js` is one 1589-line global-scope script holding all DOM handles, state, and rendering. The single highest-payoff structural work is splitting `app.js` into ES modules.
- **8 confirmed bugs (adversarially verified): 0 critical, 5 medium, 3 low.** They cluster in two places: the live-traffic / SSE path in `app.js` (5 bugs) and the sudo/pfctl child-process handling in `firewall.ts` (1 medium DoS). None are data-loss, but two are user-facing process crashes / memory leaks.
- **The three must-fix bugs are:** (1) an unhandled `stdin` `error` event that can crash the whole server on a wrong sudo password (`firewall.ts`), (2) 32-bit truncation of byte counters that corrupts throughput above ~2.1 GB (`app.js`), and (3) an unbounded `liveTraffic` Map that leaks memory across a session (`app.js`). All three are small, contained fixes.
- **Accessibility is the weakest axis and the cheapest to fix.** No global focus ring, no `prefers-reduced-motion` guard on the always-animating radar, process rows are mouse-only, modals don't trap or restore focus, multiple text/background pairs fail WCAG AA, and live data has no screen-reader story. Most of this is hours of CSS/attribute work.
- **The information architecture is inverted.** The biggest pixels (the 300–440px radar, the 42px throughput numbers) carry the least decision value, while the actual threat-handling controls (Block/VT) are hidden two interactions deep at 10px. The radar's position encodes geographic distance, not risk — decoration competing for the most screen space.
- **Product positioning is clear: a live read-only monitor (Private Eye / bandwhich tier) with enrichment (geo, rDNS, VirusTotal) and one-shot pfctl blocking.** It is not a rules-based firewall, not a historical-graph tool, not a packet analyzer. The biggest competitive gaps follow directly: no persistent rules, no history/time-travel, no inbound monitoring, no alerting.
- **Over-engineering risk is real and must be resisted.** Per the project's "prefer the 50-line solution" rule: the `app.js` split needs native ESM + one `EventTarget` bus — no framework, no bundler, no signals library. Two backend "duplications" (the two address parsers, the three IP validators) should be **left alone** because merging them adds branches, not clarity.
- **One stale doc to fix immediately:** `CLAUDE.md` still claims a `globe.gl` / Three.js 3D globe; the app actually uses a hand-rolled 2D canvas radar + `topojson-client`. There are no `globe.gl`/three dependencies anywhere.

---

## 2. Strengths

**Backend architecture (genuinely good):**
- Small, single-purpose modules with sharp comments and no god-objects. The largest files are large only for legitimate reasons (the ~160-entry process DB in `process-info.ts`; the dual continuous/one-shot sampler state machine in `traffic-stream.ts`).
- Strict-mode discipline holds: **no `any` found anywhere in `src/`**. Gaps are only at external boundaries (parsed `fetch().json()`).
- Solid security middleware in `index.ts`: binds `127.0.0.1` only, `Host`-header allowlist (DNS-rebinding defense), `Origin` allowlist, and a custom `x-requested-by` header on state-changing requests. Firewall calls use argv-form `pfctl` (never a shell) and reject loopback/unspecified IPs to prevent self-lockout.

**Frontend craft (high, despite the monolith):**
- In-place SSE byte patching (`connectTrafficStream`) updates row text by `data-traffic-key` without re-rendering the list.
- `computeRenderSig` render-skip guard deliberately excludes volatile byte counts so traffic doesn't thrash the DOM on every 2s poll.
- `ResizeObserver` / `IntersectionObserver` / `visibilitychange` gating pauses the radar when off-screen or hidden.
- Password hygiene: the sudo password is zeroed after use and never stored client- or server-side.
- OKLCH design tokens, a density toggle, and a debounced search across process/IP/domain/country/ISP.

**Product differentiators (vs. competitors):**
- Per-connection live RX/TX grouped by process **plus** geo + rDNS + VirusTotal reputation in one view — neither `bandwhich`/`nettop` (no enrichment) nor Little Snitch (weaker live rate) does this combination.
- Browser-based localhost dashboard (remote-viewable, screenshot-able, customizable) where every macOS peer is a native app.
- System health (CPU/mem/load) co-located with network data — "is my machine hot *and* is something exfiltrating?" in one pane.
- Integrated kill-process action (firewalls block the connection; they don't terminate the process).
- Open / self-hosted / free on macOS with enforcement — OpenSnitch/Portmaster are Linux/Windows only; LuLu is an app-firewall, not a live dashboard.

---

## 3. Weaknesses

- **`app.js` is a 1589-line global-scope monolith** — ~50 top-level DOM `const`s and shared mutable state, no `export`/`import`, loaded as a classic `<script>` (not a module). All rendering reads module-level globals.
- **The live-traffic / SSE path is the bug epicenter** — 32-bit truncation, an unbounded leaking Map, stale baselines on reused 5-tuples, frozen readouts when traffic idles, and an invisible stream-down state (see §4).
- **One server-crash vector** — unhandled `stdin` `error` on the sudo/pfctl child (`firewall.ts`); a wrong password or slow sudo can race and take down the process.
- **Accessibility is broadly broken** — no focus ring, no reduced-motion guard, mouse-only rows, untrapped modals, AA contrast failures, no `aria-live` (see §6).
- **Inverted information hierarchy** — decoration (radar, giant throughput numbers) dominates; the actual security task (spot → investigate → kill/block) is buried and tiny.
- **No responsive story** — fixed pixel grid columns (`880px`/`320px`/`280px`) plus `body { overflow:hidden }` mean a laptop/tablet viewport simply clips content with no scroll fallback.
- **No automated tests and no linter** — the only safety net is `tsc`, which doesn't even cover `public/`. This makes the `app.js` split riskier than it should be.
- **Three near-identical `spawn`+stdin+timeout wrappers** in the backend (real, fixable duplication) and a handful of repeated front-end flows (block/unblock, modal-overlay boilerplate).
- **Product gaps vs. peers** — no persistent rules, no history, no inbound monitoring, no alerting, no auto-updating blocklists (see §8).
- **Stale documentation** — `CLAUDE.md` describes a `globe.gl` 3D globe that does not exist in the codebase.

---

## 4. Confirmed Bugs

8 confirmed (adversarially verified): **0 critical, 5 medium, 3 low.** Ordered critical → low.

| Severity | File : location | Issue | Fix |
|---|---|---|---|
| **Medium** | `src/firewall.ts` : `validateSudo` (40–54), `loadAnchorRules` (60–74) | Unhandled `'error'` on the child **stdin** stream. The 5s timeout `SIGKILL`s the child or sudo exits on a wrong password mid-write → `child.stdin.end(...)` fails with EPIPE/`ERR_STREAM_DESTROYED`. The only handler is `child.on('error', …)` (the *ChildProcess* event, not the stream's), so the stdin error is uncaught and **crashes the whole Node process**. DoS via a wrong password or slow sudo. | Attach a no-op stdin error handler before writing in both functions: `child.stdin.on('error', () => {});` (close/exit already drives resolve/reject). Apply to any other `child.stdin.end(...)` callsite. |
| **Medium** | `public/app.js` : SSE delta handler (1117–1122) | Byte counters stored with `e.bytesIn | 0` / `e.bytesOut | 0`. JS bitwise OR coerces to **32-bit signed**, so any cumulative total above ~2.1 GB wraps negative. The stored baseline is then wrong, the next `Math.max(0, e.bytesIn - prevBytes.bytesIn)` yields garbage/zero, and the throughput graph corrupts. The raw `e.bytesIn` passed to `formatBytes()` on the same lines is *not* truncated, so row text and graph disagree. | Store untruncated: `liveTraffic.set(e.key, { bytesIn: e.bytesIn, bytesOut: e.bytesOut })`. JS safely represents integers to 2^53; no coercion needed (`>>> 0` is also wrong — caps at 4 GB). |
| **Medium** | `public/app.js` : Map decl (69), only ever `.set()` in SSE handler (1122) | **`liveTraffic` Map grows unbounded (memory leak).** Keyed by the 5-tuple `trafficKey`; only ever `.set()`, never `.delete`/`.clear`. Ephemeral connections (TIME_WAIT, short UDP, browser sockets) churn endlessly, so every new local port leaks a permanent entry. Over hours it accumulates tens of thousands of dead entries that every render path (`procSummary`, `renderConnBlock`, `renderTopTalkers`, `radarUpdateTargets`) reads. | In `fetchConnections`, after `lastData = data`, build `new Set(data.flatMap(p => p.connections.map(c => c.trafficKey)))` and delete any `liveTraffic` key not in it. Also fixes the stale-baseline bug below. |
| **Medium** | `public/app.js` : SSE handler (1102–1139) / `pushThroughput` (1143–1151); server gate `src/traffic-stream.ts` :94 | **Throughput readout & graphs freeze (never decay to 0) when traffic stops.** `pushThroughput` is only called from the SSE delta handler, and the server emits a delta *only* when `delta.length > 0`. On an idle second no event fires, so the Download/Upload numbers and sparklines stay pinned at the last non-zero value — misleading the operator that traffic is ongoing. | Add a client idle-decay: track `lastDeltaAt`, run a ~1000ms `setInterval` that calls `pushThroughput(0, 0)` once `now - lastDeltaAt >= ~1500ms`. Pause it when `document.visibilityState !== 'visible'`. |
| **Medium** | `public/app.js` : SSE handler (1102–1139); status set in `fetchConnections` :506 | **EventSource never closed and stream-down state is invisible.** The `'error'` handler is empty; `statusText` is hard-coded to `'streaming · live'` by the poll regardless of SSE health. A dead stream (e.g. server 4xx, which EventSource will *not* retry) shows a green "live" badge while RX/TX are frozen. The `es` handle escapes scope, so there's no app-level teardown/reconnect. | Hoist `es` to module scope. In `'error'` set a degraded status (`'stream offline'` + `.err`); clear it on `'open'`/first `'delta'`. Optionally expose `closeTrafficStream()` for explicit reconnect. |
| **Low** | `public/app.js` : SSE handler (1113–1122) | **Reused 5-tuple keeps a stale byte baseline → silently undercounts throughput.** Because `liveTraffic` is never pruned, when a closed connection's local port is reused, nettop reports a fresh small count while `liveTraffic` holds the old large one; `Math.max(0, small - large)` = 0, dropping that connection's traffic from the per-second rate. | Prune `liveTraffic` per poll (fix above). Additionally treat a decreasing counter as a reset: if `e.bytesIn < prevBytes.bytesIn`, count the full `e.bytesIn` rather than 0. |
| **Low** | `src/geolocation.ts` : `lookupIPs` (96–110) | **Batch rate-limiter races.** `lastBatchTime` is a single global read-then-await-then-write with no mutex. Two concurrent callers read the same value, both pass the gate, and both `fetch` ip-api.com in the same instant — the promised 1.5s spacing isn't enforced across concurrent calls, so the 45 req/min free tier can be exceeded (→ 429s, silently dropped geo). `lookupSingleIP` bypasses the limiter entirely, compounding the burst. | Serialize batches through a shared promise chain (like block-store's `serialize()`); set `lastBatchTime` to the *scheduled* send time before awaiting, not after. Route `lookupSingleIP` through the same limiter. |
| **Low** | `src/routes.ts` : `GET /api/host-info` (248–257) | **`localIP` picks the last interface, not the primary.** The inner `break` only exits the inner loop; the outer interface loop keeps going, so `localIP` becomes the first IPv4 of the *last* non-internal interface. With Wi-Fi + Ethernet + VPN `utun` + Docker `bridge100` active, it can report a Docker/VPN address as the host's LAN IP. | Break out of both loops on first match (labeled `outer:` or a helper that returns), or explicitly prefer `en0`/`en1` and skip `bridge`/`utun`. |

---

## 5. Refactor Recommendations

**Backend is in good shape — the frontend is the work.** Headline: split `app.js`. Everything below is ordered biggest-payoff / least-risk first. Each step is independently shippable.

### 5.1 The main event: `app.js` → ES modules

**Why it's low-risk:** `app.js` is already sectioned with 24 `// ----------` banners. The split follows those banners almost 1:1 — mechanical extraction, not a redesign. Coupling is shallow (render functions read module-level `liveTraffic`/`blockedIPs`/`lastData`).

**Prerequisite (one line, do first):** change `index.html:254` from `<script src="app.js">` to `<script type="module" src="js/main.js">`. This unlocks native `import`/`export` with **zero bundler** (CSP already allows `script-src 'self'`).

**Proposed split (~9 files under `public/js/`):**

| File | Responsibility | ~LOC |
|---|---|---|
| `dom.js` | All `getElementById` handles, exported as a frozen `el` object | ~55 |
| `state.js` | Shared mutable state + the tiny event bus (below) | ~40 |
| `util.js` | Pure helpers (`escapeHtml`, `isIPv6`, `isPrivateIP`, `flag`, `formatBytes`, `relTime`, `looksLikeIP`) — no DOM, no state → unit-testable | ~110 |
| `api.js` | `apiFetch` + one thin fn per endpoint; returns parsed data, no rendering/toasts | ~90 |
| `connection-list.js` | The process queue: sort/filter/`renderQueue`/row rendering + queue listeners | ~310 |
| `radar.js` | Self-contained canvas radar (already nearly standalone) | ~330 |
| `panels.js` | Throughput graph + system-health + host-info masthead + clock + tweaks | ~140 |
| `modals.js` | Toasts, confirm/sudo dialogs, VT modal, blocked-history modal | ~400 |
| `sse.js` | `connectTrafficStream` | ~40 |
| `main.js` | Entry point: imports, wires `refreshAll`/`scheduleRefresh`, kicks off stream | ~40 |

**The one design decision — kill the implicit `renderQueue()` coupling.** ~10 call sites poke `renderQueue()` across future module boundaries → circular-import tangle. Fix with a tiny `EventTarget` bus in `state.js` (~15 lines), `emit('data:changed')` / `on('data:changed', renderQueue)`. **Do NOT reach for a framework, signals lib, or store abstraction** — one `EventTarget` is the whole architecture.

**Don't regress during the split:** keep the `computeRenderSig` skip-guard intact; `sse.js` and `connection-list.js` must import the **same** `liveTraffic` instance from `state.js`; radar's observer wiring moves *with* the radar code.

**Safety net (strongly recommended):** the split makes `util.js` purely testable for the first time. Land a handful of `node --test` unit tests against `escapeHtml`/`isPrivateIP`/`formatBytes`/`looksLikeIP` — near-zero cost, pins the riskiest pure logic. Otherwise the only gate is manual `pnpm dev` click-through. Do radar/sse/panels as separate commits from connection-list/modals.

### 5.2 Backend tidy (lower urgency — backend isn't hurting)

- **`runWithInput` spawn helper (medium, real dup).** `validateSudo`, `loadAnchorRules` (firewall.ts) and `getTrafficSnapshot` (traffic.ts) are three copies of "spawn, buffer stdout/stderr, optional stdin, 5s timeout-kill." Factor one ~25-line helper. **Caveat:** keep it ~25 lines — do not generalize into a streaming framework.
- **`routes.ts` mixes routing with logic (medium).** Extract `buildConnectionsPayload` + coalesce window → `connections-service.ts`, and host-info gathering + 5-min cache → `host-info.ts`. `routes.ts` becomes a thin ~120-line path→handler→`res.json` map. Pure move, low risk.
- **`ActionResult` type (low).** firewall/kill/vt/delete all return `{ success, message }`. Add `export interface ActionResult { success: boolean; message: string }` to `types.ts` and reuse — removes 4+ inline duplicate literals. Also move `SystemHealth` into `types.ts` for findability.
- **Type the `fetch().json()` boundaries (low).** `geolocation.ts:57/114`, `routes.ts:264` cast inline `any`-shaped upstream JSON. Move those interfaces (`IpApiResult`, `IpifyResult`) into `types.ts`. This is the real `unknown`-narrowing spot the "no `any`" rule targets.

### 5.3 Front-end de-dup (after the split)

- **`runFirewallAction(action, ip, {onSuccess})`** collapses the 5× block/unblock flow (~40 lines) and centralizes password-scrubbing that's currently easy to forget.
- **`createOverlay(id, html, {onClose})`** (~15 lines) collapses the 6× modal-overlay boilerplate. Keep it dumb — no modal framework.
- **Delete the client `isPrivateIP` copy** — the server already classifies private IPs (`countryCode:'LO'`); the front end can key off `conn.geo?.countryCode === 'LO'` (or a new server `isPrivate` boolean). Cleaner than sharing code across the runtime boundary without a bundler.
- **Delete `fmtBytes`** (the GB/MB-only duplicate of `formatBytes`); lands naturally with `util.js`.

### 5.4 Zero-risk cleanups (minutes, no behavior change)

- Delete `tempC`/`TEMP_C` in `system-health.ts` — always `null`, in the interface, **no consumer reads it**.
- Drop the `export` on `reverseLookup` (only used internally).
- **Fix the `globe.gl` doc references in `CLAUDE.md`** (Stack + Frontend sections) — the app uses a 2D canvas radar + `topojson-client`, no globe.gl/three anywhere.

### Over-engineering guardrails (per the "50-line solution" rule)
- **Leave the two address parsers alone** (`parseAddress` in connections.ts vs `parseEndpoint` in traffic.ts) — they parse genuinely different formats (lsof `[v6]:port` vs nettop `v6.port`); merging adds detection branches.
- **Leave the three IP validators alone** (`isBlockableIP`, `isIP()`, `looksLikeIP`) — they validate for different purposes; consolidating couples unrelated concerns.
- If a "helper" starts growing options/config, that's the signal you've overshot.

---

## 6. UI/UX Improvements

The craft is high; the problems are **task focus** and **accessibility**, not polish.

### 6.1 Accessibility (weakest axis, cheapest fixes — do first)

- **No global focus ring** anywhere (`button { border:0 }`, no `:focus-visible`) — a WCAG 2.4.7 failure across every control. Add `:focus-visible { outline: 2px solid var(--ice); outline-offset: 2px; }` and `.row:focus-within .kill { opacity:1 }`.
- **No `prefers-reduced-motion` guard** — the radar sweep animates continuously (~1 rev/7s) plus pulsing rings, with infinite `pulse`/`spin` keyframes. Gate `scheduleRadarFrame` on `!matchMedia('(prefers-reduced-motion: reduce)').matches` (draw one static frame), and disable the infinite animations under the media query.
- **Contrast failures on the dark theme.** `--ink-mute (L≈0.40)` labels content (`.row .idx`, `·SYS`, placeholders, 9–10px section labels) on an `L≈0.13` background; `--ink-dim (L≈0.58)` is the default for `.row .meta` at 10px. Lift both tokens (`--ink-dim → ~0.72`, `--ink-mute → ~0.62`) and stop using `--ink-mute` for actual content — one edit fixes the majority of failures.
- **Process rows are mouse-only.** `.row` is a `<div data-action="toggle">` with no `tabindex`/`role`/key handler — the core of the app can't be driven from the keyboard. Add `tabindex="0"`, `role="button"`, `aria-expanded`, Enter/Space handling.
- **Modals don't trap or restore focus and aren't announced.** Add `role="dialog" aria-modal="true" aria-labelledby`, store/restore `activeElement`, trap Tab, and a document-level `Esc` (the confirm dialog has no Esc at all). The sudo input auto-focus is the only correct piece today.
- **Unnamed controls / no live regions.** Add `aria-label` to `#searchInput`, `#blockedSearch`, `#sortSelect`, `#refreshSelect`, `#refreshNowBtn`, the `×`/`⟲`/`🗑` glyph buttons (the wastebasket reads literally as "wastebasket"); `aria-pressed` on filter chips; `role="status"` on `#statusText`; `aria-live="polite"` on the connection count / any new-threat indicator. The radar `<canvas>` needs an `aria-label` or `aria-hidden`.

### 6.2 Usability quick wins (hours)

- **Show "(N hidden)" on active filter chips** (the `.chip .count` style exists but is unused) and add a **"Clear filters"** button to the empty state — three filters default on (`sys/v6/priv`), so users may wrongly conclude "nothing is connecting."
- **Disable action buttons in-flight** for kill/block/VT (mirror the existing `.blocked-row-remove` spinner pattern) — a double-click currently fires two sudo modals.
- **Add a confirm or undo for user-process kills** — today user processes are killed silently with no dialog while every *reversible* block pops a heavy sudo modal. The friction is backwards.
- **Inline error + Retry in `#queue`** on `fetchConnections` failure (the status currently only changes in the far-away masthead; `fetchHostInfo`/`fetchBlockedIPs` swallow errors silently → stale data with no signal).
- **Restyle the sudo "Proceed" button** off the red `.confirm-kill` style — a password prompt isn't a destructive confirmation.
- **Flash new rows** — apply the already-defined-but-unused `.flash`/`flashFx` keyframe to connections/processes new this render. In a security tool, *a connection appearing* is the single most important event, yet it currently looks identical to a re-sort.
- **Toasts stack-replace** (a burst of bulk results clobbers earlier messages) and auto-dismiss in 3s — consider stacking or persisting failures.

### 6.3 Larger redesigns (schedule deliberately)

- **Rebalance the IA.** Demote the radar (collapse by default or a "Map" tab), shrink its grid track, and give primacy to the connection list. Promote blocked-IPs from a squeezed `grid-row:4` footer to a peer panel. Remove the duplicated host info (masthead **and** `.queue-netinfo`).
- **Introduce a risk model on rows** — a per-connection risk badge (new destination, blocked-ASN neighbor, VT-flagged) visible while collapsed, plus a "Recently appeared" sort / "new since last refresh" filter. Today every row looks identical regardless of risk.
- **Responsive layout** — replace fixed `880px`/`320px`/`280px` columns with `minmax`, add a sub-~1100px breakpoint that stacks queue/stage, and allow `.main` to scroll instead of `overflow:hidden` clipping.
- **Unify the three "traffic" representations** — global rate (42px) vs. per-row *cumulative* bytes vs. radar top-3-by-volume are three inconsistent notions. Surface the per-connection *rate* you already compute (`drx/dtx`) so a throughput spike maps to a culprit connection.

> **The single biggest UI/UX recommendation:** fix accessibility first (focus ring + reduced-motion + keyboard-operable rows + contrast token lift) — it's the weakest axis, the cheapest to fix, and most of it is hours of CSS/attribute work — then rebalance the inverted information hierarchy so the connection list (not the radar/throughput) owns the primary pixels.

---

## 7. Modern Design Direction

**Thesis: NetWatcher is an instrument panel, not a hero page.** Treat it like the Linear/Vercel surface — near-black canvas, monochrome-first with ONE accent, ruthless data density, and motion used only to signal *change*.

### Keep or replace the radar? **Replace it.**
A 2D sweeping radar is a gimmick: angle and the rotating beam carry no data, "hot" is decided purely by byte volume (your Netflix stream is "hot"; a 200-byte C2 beacon is a cold dot), and for **localhost** monitoring geography is the wrong primary axis entirely. Live "threat maps" and radar sweeps are marketing/lobby-screen artifacts, not analyst tools.

**Replace with a deterministic radial topology graph:** localhost at center, endpoints on concentric rings grouped by process or ASN/domain. Edge thickness = throughput, animated dashes (`stroke-dasharray`/`stroke-dashoffset`) = live flow, node color = risk. This keeps the circular silhouette (if it's emotionally load-bearing for the product) but makes **every visual property data-bearing**. Use a deterministic radial layout (angle from a stable endpoint hash), not force-physics — stable positions make anomalies pop and avoid the jittery "hairball." This is the legitimate evolution of the radar idea (cf. Netflix Vizceral, sFlow Particle).

### The system (all vanilla CSS custom properties, no build step)
- **Surfaces:** pure black only for the outer canvas; **near-black grays for content surfaces** with elevation via *lightness*, not shadows (`--bg-canvas #0A0A0A → --bg-surface #121212 → -2 #1A1A1A → -3 #232323`). Borders = low-opacity white hairlines (`rgba(255,255,255,0.08)`).
- **One accent** (electric cyan `#3DD4FF`) for active/selected/focus/live-pulse only; the rest grayscale.
- **Colorblind-safe status (non-negotiable for a security tool):** do NOT rely on red/green (collapses for protan/deutan). Use a blue↔orange axis, keep green only as a tertiary "ok" with a ✓ glyph, and **always pair color + icon + text**. Target WCAG 4.5:1 text / 3:1 UI. Test with Chrome DevTools → Rendering → Emulate vision deficiencies.
- **Type:** variable sans (Inter/Geist) for UI; monospace with **`font-variant-numeric: tabular-nums`** (mandatory) for IPs/ports/bytes/timestamps so live numbers don't jitter. Scale 11/12/13/14/16/20/28/40.
- **Spacing:** 8px grid (4/8/12/16/24/32). Tight card padding (12–16px), clear card gaps (16–24px), row height ≥ 32px.
- **Charts:** boring proven types — sparklines (top bar + per row), one stacked-area throughput panel, top-N horizontal bars. `<canvas>` ring-buffer + `requestAnimationFrame` for time series; SVG for the topology (for flow animation + hit-testing).

### Real-time mechanics
~1s update cadence for numbers; **append, don't redraw**; **decouple data from paint** (buffer samples, paint on rAF); **add a Pause / freeze toggle** (a hard requirement for monitoring tools — analysts need to stop the stream to inspect). Reserve 60fps purely for the cheap GPU flow animation.

### Motion: help, don't distract
Fade-in (150–200ms) on new data/rows; a gentle 2s "live" pulse that **goes solid when paused/stale** (absence of motion carries meaning); subtle hover cross-highlight (row → chart line → topology node). No spinning, no continuous non-data-bound motion, nothing slower than ~250ms in steady state, animate only `transform`/`opacity`. **Always gate on `prefers-reduced-motion: reduce`.**

### Highest-leverage additions
A collapsible icon nav rail + a **`⌘K` command palette** (pure vanilla JS — a filtered fuzzy list) is the single biggest power-user win.

---

## 8. New Feature Suggestions

Positioning: NetWatcher is a **live read-only monitor with enrichment + one-shot blocking** — not a rules firewall, history tool, or packet analyzer. Difficulty rated against the existing `lsof + nettop + pfctl + SSE + localhost-web` stack.

| # | Feature | Use case / who | Difficulty | Value |
|---|---|---|---|---|
| **1 ★** | **Persistent rule engine** (allow/deny per IP/CIDR, auto-reapply on launch) | Privacy users/devs who want a block to *stay* blocked across reboots + allow-lists to de-clutter | Medium — persist to a pf anchor + JSON store, reload via launchd; v1 per-IP, v2 per-process | **Very high** — converts observation → enforcement |
| **2 ★** | **Historical recording + time-travel graphs** | "Did something spike at 3am?" / per-app daily totals (GlassWire/vnstat parity) | Medium — sample the nettop stream into SQLite rollups / ring-buffer; reuse the dashboard to chart | **Very high** — most-cited gap after rules |
| **3 ★** | **Inbound + listening-socket monitoring** | Spot unexpected servers/backdoors; "what's listening on this port?" | **Low** — `lsof` already returns `LISTEN`/inbound sockets; mostly parsing + a new tab | **High** — widens the security claim cheaply |
| **4 ★** | **Alerting / notifications** (new process phoning home, flagged-IP hit, data-cap) | Users who can't watch the dashboard all day | Low–Medium — server-side rule eval + macOS notifications / webhook / toast | **High** — passive guardian, not just a console |
| **5 ★** | **Auto-updating threat/ad/tracker blocklists + domain grouping** | Auto-flag trackers/C2 without manual VT lookups; read connections by service, not raw IP | Medium — ingest public lists on a timer, match live, group rows by rDNS/domain (cache to spare VT) | **High** — with #1, approaches Little Snitch enforcement |
| 6 | Menu-bar companion app (`NSStatusItem`/rumps) | At-a-glance status + quick block/pause without a browser tab | Medium — thin native client over the existing localhost API | Medium-high |
| 7 | Rich data export + read API (CSV/JSON of live + historical) | Incident responders, scripters, SIEM feeds | Low (esp. after #2) — `/export?format=…` endpoints | Medium |
| 8 | Connection/process drill-down (full path, parent, **code-signature**) | "Is this real Zoom or malware named zoom?" | Low–Medium — `codesign -dv`/`lsof` already expose it | Medium |
| 9 | Per-app bandwidth throttling (pf `dummynet`) | Match Murus "Snail" | High — dummynet pipes are per-IP and fiddly | Niche |
| 10 | DNS encryption (DoH/DoT) | Privacy parity with Little Snitch/Portmaster | High — needs a local resolver/proxy | Medium, off-mission — defer |
| 11 | Wi-Fi-network-aware rule profiles (needs #1) | Auto-switch home/office/public policy | Medium | Medium |

**Explicit non-goal to document:** deep packet inspection — cede that to Wireshark; the lsof/nettop architecture sees sockets, not payloads, and chasing DPI would dilute the product.

---

## 9. Suggested Roadmap

Three phases, each independently shippable, sequenced for biggest-payoff / least-risk first.

### Phase 1 — Stabilize & make it accessible (days)
*The cheap, high-impact safety and a11y work — no architecture churn.*
1. **Fix the 3 must-fix bugs:** stdin error handler (`firewall.ts`, crash), 32-bit byte truncation (`app.js`), unbounded `liveTraffic` leak (`app.js`) — and the four follow-on `app.js` traffic bugs ride along with the prune fix.
2. **Accessibility quick wins:** global focus ring, `prefers-reduced-motion` guard, keyboard-operable rows, lift the two contrast tokens, name controls + `role="status"`/`aria-live`, modal focus-trap/restore.
3. **Usability quick wins:** "(N hidden)" chips + Clear-filters empty state, in-flight button disabling, kill confirm/undo, inline error+Retry, flash new rows.
4. **Zero-risk cleanups:** delete `tempC`/`fmtBytes`, fix the `globe.gl` doc in `CLAUDE.md`, add `ActionResult` to `types.ts`.

### Phase 2 — Refactor the frontend & tidy the backend (1–2 weeks)
*Pay down the structural debt now that behavior is stable.*
1. **Split `app.js` into ~9 ES modules** behind `<script type="module">` + the one `EventTarget` bus — extract leaf-first (util/dom/state → api → radar/sse/panels → connection-list/modals → main), verifying after each commit. Land `node --test` unit tests against `util.js` as the safety net.
2. **De-dup the now-modular front end:** `runFirewallAction`, `createOverlay`, drop the client `isPrivateIP` in favor of the server `LO`/`isPrivate` signal.
3. **Backend tidy:** `runWithInput` spawn helper (3 copies → 1), extract `connections-service.ts` + `host-info.ts` from `routes.ts`, type the `fetch().json()` boundaries.

### Phase 3 — Grow the product & redesign (weeks+)
*The differentiating features and the design direction, on a stable, modular base.*
1. **Top-5 features in value order:** persistent rules (#1) → history/time-travel (#2) → inbound monitoring (#3) → alerting (#4) → auto-updating blocklists + domain grouping (#5). #4 and #7 (export) fall out cheaply once #2 exists.
2. **Design redesign:** rebalance the IA (demote/redefine the radar → radial topology, promote blocked-IPs, primary pixels to the connection list), introduce the per-row risk model, add responsive breakpoints, add the `⌘K` command palette + Pause toggle, adopt the colorblind-safe token system.

> **Guardrail throughout:** prefer the 50-line solution. No frontend framework / bundler / signals library (native ESM + one `EventTarget`). Keep helpers small. Leave the two address parsers and three IP validators as-is.

---

## Sources

**Modern design research:**
- Grafana — Dashboard best practices: https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/
- Datadog — Designing effective dashboards: https://www.datadoghq.com/blog/datadog-executive-dashboards/
- Datadog — Network Traffic Visualization: https://www.datadoghq.com/monitoring/network-traffic-visualization/
- Netflix Vizceral: https://github.com/netflix/vizceral
- sFlow — Particle (real-time traffic viz): https://blog.sflow.com/2018/07/visualizing-real-time-network-traffic.html
- sFlow — Real-time viz using Vizceral: https://blog.sflow.com/2017/09/real-time-traffic-visualization-using.html
- Qodequay — Dark Mode Design for Data-Heavy Dashboards: https://www.qodequay.com/dark-mode-dashboards
- SeedFlip — Vercel Design System Breakdown: https://seedflip.co/blog/vercel-design-system
- LogRocket — Linear design: https://blog.logrocket.com/ux-design/linear-design/
- UITop — Top Dashboard Design Trends 2025: https://uitop.design/blog/design/top-dashboard-design-trends/
- Tableau — Don't use red & green together: https://www.tableau.com/blog/examining-data-viz-rules-dont-use-red-green-together
- David Nichols — Coloring for Colorblindness: https://davidmathlogic.com/colorblind/
- WebAbility — Colors to avoid for color blindness: https://www.webability.io/blog/colors-to-avoid-for-color-blindness
- Northeastern (thesis) — Cybersecurity Visualization Design Approaches: https://repository.library.northeastern.edu/files/neu:4f22wv79b/fulltext.pdf
- NJ Tech Pioneers — Microinteractions & motion in UX 2025: https://njtechpioneers.com/blog/how-microinteractions-and-motion-are-shaping-ux-in-2025/
- Medium (Moonsoonfish) — Dark mode done right 2026: https://medium.com/@social_7132/dark-mode-done-right-best-practices-for-2026-c223a4b92417

**Competitor / feature-gap research:**
- Little Snitch: https://www.obdev.at/products/littlesnitch/index.html
- LuLu (Objective-See): https://objective-see.org/products/lulu.html · https://github.com/objective-see/LuLu
- GlassWire: https://www.glasswire.com/features/ · https://www.glasswire.com/android-help/
- Radio Silence vs Little Snitch: https://radiosilenceapp.com/radio-silence-vs-little-snitch
- Murus / Vallum: https://www.murusfirewall.com/ · https://www.vallumfirewall.com/endpointsecurity/ · https://murusfirewall.com/comparison/
- Private Eye: https://osxdaily.com/2011/10/28/monitor-network-connections-mac-os-x-private-eye/ · https://radiosilenceapp.com/private-eye/
- bandwhich: https://github.com/imsnif/bandwhich
- nettop (man page): https://manp.gs/mac/1/nettop
- iftop / vnstat / bandwidth tools: https://linuxize.com/post/network-bandwidth-monitoring-tools/
- Wireshark: https://www.wireshark.org/ · https://www.wireshark.org/docs/wsug_html/
- OpenSnitch: https://github.com/evilsocket/opensnitch
- Portmaster: https://www.helpnetsecurity.com/2025/12/03/portmaster-open-source-application-firewall/ · https://www.blog.brightcoding.dev/2026/04/18/portmaster-the-privacy-firewall-every-developer-needs
