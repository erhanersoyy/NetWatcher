# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

- Node.js, TypeScript (strict), Express 5, Vanilla JS frontend
- pnpm 9.15.4 (via corepack), tsx for dev
- macOS only (depends on `lsof`)

## Commands

- `pnpm dev` — start dev server at http://localhost:3847 (tsx watch, auto-restarts)
- `pnpm typecheck` — run after a series of edits
- `pnpm build` — compile TS to `dist/`
- `pnpm start` — run compiled build
- `pnpm test` — run unit tests (Node's built-in runner over `src/**/*.test.ts` and `public/**/*.test.js`)

No linter is configured yet.

## Architecture

Single-process Node.js server: Express backend serves a static vanilla JS frontend and a REST API.

### Backend (`src/`)

- **`routes.ts`** — REST API:
  - `GET /api/connections` → `ProcessInfo[]` grouped by PID, sorted by connection count. Enriches each connection with geo, reverse DNS, process metadata.
  - `POST /api/kill/:pid` → SIGTERM after verifying PID ownership
  - `POST /api/block/:ip` / `POST /api/unblock/:ip` → add/remove IP in the `netwatcher` pfctl anchor/table
  - `GET /api/blocked` → list of currently blocked IPs
  - `GET /api/vt/:ip` → VirusTotal reputation via the local `vt` CLI (if installed)
  - `GET /api/host-info` → local IP, public IP (via ipify.org), hostname, geo. Cached 5 min.
- **`index.ts`** — Express app + security middleware: binds to `127.0.0.1` only (aborts if not), enforces `Host` header allowlist (DNS-rebinding defense), `Origin` allowlist when present, and a custom `x-requested-by: netwatcher` header on every state-changing request.
- **`connections.ts`** — Parses `lsof -i -n -P -F pcPtTn` machine-readable output. The `-F` flag uses single-char prefixes per line (`p`=PID, `c`=command, `P`=protocol, `T`=state, `n`=name) — not column-based. Handles IPv6 bracket notation.
- **`geolocation.ts`** — Batch IP lookups via ip-api.com (`POST /batch`, up to 100 IPs). In-memory 24h cache. Private IPs get synthetic `Local` geo. 1.5s minimum between batch requests. Also exports `lookupSingleIP` and `isPrivateIP`.
- **`dns-resolver.ts`** — Reverse DNS via `dns/promises.reverse()`. 30-min cache. Deduplicates concurrent lookups for same IP. Failures return `'-'`.
- **`process-info.ts`** — Hardcoded DB of ~160 process names mapping to 2-3 word descriptions and `isSystem` flag. Fallback: `com.apple.*` → system. Used for the "?" info badge and kill confirmation on system processes.
- **`process-kill.ts`** — Verifies PID belongs to current user by comparing numeric uid (not username — `ps -o user=` truncates at 8 chars on macOS), then sends SIGTERM.
- **`firewall.ts`** — Manages the `netwatcher` pf anchor + `netwatcher_block` table via `sudo /sbin/pfctl` (argv-form, never a shell). Sudo password is supplied per request by the UI (piped to `sudo -S` over stdin, never stored). Rejects loopback/unspecified IPs to prevent self-lockout.
- **`virustotal.ts`** — Wraps the `vt ip <ip>` CLI (brew install virustotal-cli; `vt init` for the API key). 10-min in-memory cache.

### Frontend (`public/`)

- **No build step** — native ES modules served as static files. Entry point: `js/main.js` loaded as `<script type="module">` in `index.html`
- **Module layout:**
  - `main.js` — thin bootstrap entry point
  - `dom.js` — cached element handles + render helpers
  - `state.js` — shared state object + tiny `EventTarget`-based bus (`emit`/`on`) for decoupled event flow
  - `util.js` — pure helper functions (includes unit tests in `util.test.js`)
  - `api.js` — HTTP fetchers for `/api/*` endpoints; emit bus events instead of calling render directly
  - `connection-list.js` — render + filter + sort process cards
  - `radar.js` — 2D canvas radar with rotating sweep, country pins (via `topojson-client`), gated by Resize/Intersection/visibility observers
  - `panels.js` — sidebar panels: throughput, idle-decay, system-health
  - `modals.js` — dialog primitives + blocked IP sidebar
  - `actions.js` — privileged actions (kill, block, unblock, VirusTotal) + blocked-history modal
  - `sse.js` — Server-Sent Events subscription for real-time connection updates
- **Bus pattern:** producers emit state-change events (e.g., `emit('data:changed')`); consumers subscribe (e.g., `on('data:changed', render)`). This decouples fetch→render and avoids circular imports.
- Filters (client-side): exclude IPv6, exclude private IPs, exclude localhost, hide system processes; text search across process/IP/domain/country/ISP
- System processes show caution badge; kill triggers a confirmation dialog

## External Services

- **ip-api.com** — Free tier, 45 req/min, no API key. Batch endpoint is critical for staying under the limit.
- **ipify.org** — Public IP detection, 5s timeout
- **unpkg.com CDN** — `topojson-client@3.1.0` (SRI-pinned `<script>`) plus the `world-atlas@2.0.2` countries TopoJSON, both fetched at runtime; `topojson-client` decodes the atlas into the radar's coastline paths. Radar renders without borders if the CDN is unavailable.

## Code Style

- ES modules (`import`/`export`), never CommonJS
- No `any` — use `unknown` + narrowing
- Prefer early returns over nested conditionals

## Gotchas

- `lsof` without sudo only shows current user's processes — this is intentional
- Geo/DNS lookup failures are silent — they return null/`'-'` and don't block rendering
- The frontend uses native ES modules with no build/bundle step; `public/js/main.js` is the entry point
- `process-info.ts` is a static knowledge base — new processes need manual additions

## Workflow

- **IMPORTANT**: run `pnpm typecheck` after a series of edits
- Conventional commits (`feat:`, `fix:`, `docs:`)
- Branch names: `feat/…`, `fix/…`, `chore/…`
