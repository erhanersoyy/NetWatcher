# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

- Node.js, TypeScript (strict), Express 5, Vanilla JS frontend
- pnpm 9.15.4 (via corepack), tsx for dev
- globe.gl (Three.js) loaded from CDN — not bundled
- macOS only (depends on `lsof`)

## Commands

- `pnpm dev` — start dev server at http://localhost:3847 (tsx watch, auto-restarts)
- `pnpm typecheck` — run after a series of edits
- `pnpm build` — compile TS to `dist/`
- `pnpm start` — run compiled build

No test runner or linter is configured yet.

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

- **No build step** — vanilla JS/CSS served as static files
- `app.js` polls `/api/connections` every 2s, renders expandable process cards
- Filters (client-side): exclude IPv6, exclude private IPs, exclude localhost, hide system processes; text search across process/IP/domain/country/ISP
- 3D globe (globe.gl): HTML pin elements with pulse animation, arc hover highlighting (dims others on hover)
- System processes show caution badge; kill triggers a confirmation dialog
- Per-row actions: VirusTotal lookup (`VT` button) and firewall block/unblock (opens/closes the pfctl entry)

## External Services

- **ip-api.com** — Free tier, 45 req/min, no API key. Batch endpoint is critical for staying under the limit.
- **ipify.org** — Public IP detection, 5s timeout
- **unpkg.com CDN** — globe.gl and three-globe assets (earth textures)

## Code Style

- ES modules (`import`/`export`), never CommonJS
- No `any` — use `unknown` + narrowing
- Prefer early returns over nested conditionals

## Gotchas

- `lsof` without sudo only shows current user's processes — this is intentional
- Geo/DNS lookup failures are silent — they return null/`'-'` and don't block rendering
- The frontend has no build/bundle step; `public/app.js` is a single vanilla JS file
- `process-info.ts` is a static knowledge base — new processes need manual additions

## Workflow

- **IMPORTANT**: run `pnpm typecheck` after a series of edits
- Conventional commits (`feat:`, `fix:`, `docs:`)
- Branch names: `feat/…`, `fix/…`, `chore/…`
