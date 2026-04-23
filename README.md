# NetWatcher

A local network-connection dashboard for macOS. Lists every outbound connection on your machine grouped by process, enriched with geo / reverse DNS / process metadata, and plotted on a 2D radar. Kill processes and block remote IPs via `pfctl` straight from the browser.

![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![node](https://img.shields.io/badge/node-%3E%3D20-green)

Everything runs on `127.0.0.1:3847`.

## Contents

- [Features](#features)
- [Install & run](#install--run)
- [UI layout](#ui-layout)
- [Block / Unblock setup](#block--unblock-setup)
- [Architecture](#architecture)
- [REST API](#rest-api)
- [Security posture](#security-posture)
- [External services](#external-services)
- [macOS pf notes](#macos-pf-notes)
- [Limitations](#limitations)
- [License](#license)

## Features

- **Live connection list.** `lsof` snapshot, grouped by PID, configurable refresh (2s / 10s / 30s / 1m / 5m / 10m + manual; default 5m). Default filters exclude IPv6, private IPs, and system processes.
- **Per-connection RX / TX bytes.** A long-running `nettop` child streams byte counts to the server; the server pushes deltas to the browser over SSE (`/api/traffic-stream`). Each connection row shows live RX / TX, and the top throughput panel aggregates download / upload.
- **Geo + reverse DNS.** Batched against ip-api.com, cached in memory (24h geo, 30min DNS).
- **2D radar.** Azimuthal-equidistant projection centered on your location, with a rotating sweep, range rings, and a pin per remote country. Top 3 by traffic burn hot (pink); rest are cool (ice). Sizes itself to its container via `ResizeObserver` — no drift when the layout changes.
- **Host info.** Masthead shows hostname / local IP / public IP / geo / ISP; the left panel repeats ISP + geo as a compact always-visible strip above the process list.
- **System health.** Live CPU / memory / temp / load readout from `src/system-health.ts`, polled from `/api/system-health`.
- **Kill process.** uid-verified `SIGTERM`, with a confirmation dialog on system processes.
- **Block / unblock IP.** `pfctl` anchor + table; per-request sudo password (never stored).
- **Blocked IPs panel + history.** The sidebar panel lists current blocks with filter / export / manual add. The history modal (`History…`) shows all past block sessions with country, hostname, reason, duration, and bulk unblock / reblock / remove actions. Persisted to `data/blocks.json` (gitignored).
- **VirusTotal lookup.** Optional, via the `vt` CLI. Modal shows stat lines (malicious / suspicious / harmless), country, ASN.
- **Graceful shutdown.** `SIGINT` / `SIGTERM` stops the traffic sampler, drains HTTP connections, force-closes keep-alives, and releases port 3847.

## Install & run

Requires macOS, Node ≥ 20, `sudo`. Prerequisites in `requirements.txt`.

```bash
./setup.sh        # tool check + pnpm + deps + typecheck

pnpm dev          # http://localhost:3847 (tsx watch)
pnpm build        # compile to dist/
pnpm start        # run compiled build
pnpm typecheck    # tsc --noEmit
```

`pnpm dev` runs a `predev` step that frees port 3847 first — if a previous `tsx watch` (or zombie child) is still holding it, the PIDs are printed and SIGTERM'd so the new run binds cleanly.

## UI layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│  NetWatcher   Host | Local | Public | Geo | ISP       12:04:37 · state │  ← masthead
├─────────────────────────┬───────────────────────────────────────────────┤
│ Process list   (n)      │                                               │
│ ISP       | Geo          │            ┌───── radar ─────┐                │
│ [sort][refresh][↻]      │            │   N   NE   E   │                │
│ [search /]              │            │  sweep + pins   │                │
│ [hide sys][no ipv6]…    │            └─────────────────┘                │
│                          ├───────────────────────────────────────────────┤
│ ▸ chrome   (45)          │   ↓ Download  2.11 MB/s   │  ↑ Upload  0.04  │
│ ▸ slack    (12)          ├───────────────────────────────────────────────┤
│   ▸ 151.101.1.69 :443    │   Processes · Connections · Countries         │
│ …                        ├───────────────────────────────────────────────┤
│                          │   Blocked IPs  (n)  [filter][export][+add]    │
│                          │   1.2.3.4  TR  evil.example  2m ago  [un]     │
└─────────────────────────┴───────────────────────────────────────────────┘
```

Press `T` for tweaks (density, radar on/off), `/` to focus the search.

## Block / Unblock setup

Block / Unblock shells out to `sudo /sbin/pfctl`. The UI shows a sudo dialog on every Block / Unblock; the password is sent once to the local server, piped to `sudo -S` over stdin, and never written anywhere. No `NOPASSWD` / sudoers configuration is used or supported.

## Architecture

```
src/
├── index.ts            # Express + Host/Origin/CSRF middleware + graceful shutdown
├── routes.ts           # REST API + SSE stream
├── connections.ts      # lsof -F parser
├── traffic.ts          # one-shot nettop byte snapshot
├── traffic-stream.ts   # long-running nettop child + SSE subscriber mgmt
├── geolocation.ts      # ip-api.com batch + 24h cache
├── dns-resolver.ts     # reverse DNS + 30min cache
├── system-health.ts    # CPU / mem / temp / load via sysctl / vm_stat
├── process-info.ts     # static process metadata (~160 entries)
├── process-kill.ts     # uid-verified SIGTERM
├── firewall.ts         # pfctl anchor / table mgmt
├── block-store.ts      # data/blocks.json atomic store
├── virustotal.ts       # `vt ip` wrapper
└── types.ts

public/
├── index.html          # no build step
├── app.js              # vanilla JS, SSE client, canvas radar
└── style.css
```

## REST API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/api/connections`         | Grouped connections with geo / DNS / traffic enrichment |
| `GET`  | `/api/traffic-stream`      | SSE; `event: delta` with per-connection RX/TX every ~1s |
| `GET`  | `/api/host-info`           | Hostname + local / public IP + geo (5m cache) |
| `GET`  | `/api/system-health`       | CPU / mem / temp / load |
| `POST` | `/api/kill/:pid`           | uid-verified SIGTERM |
| `GET`  | `/api/vt/:ip`              | VirusTotal lookup (via local `vt` CLI) |
| `POST` | `/api/block/:ip`           | Add IP to pf table (+ kill states) |
| `POST` | `/api/unblock/:ip`         | Remove IP from pf table |
| `GET`  | `/api/blocked`             | Currently-blocked IPs |
| `GET`  | `/api/block-history`       | Full block history with session rows |
| `DELETE` | `/api/block-history/:ip` | Remove one history row (`blockedAt` query param required) |

All state-changing calls require `x-requested-by: netwatcher`. Block / unblock calls also accept a one-time sudo password in the JSON body.

## Security posture

- Bound to `127.0.0.1` only; aborts if the listener ever lands elsewhere.
- `/api` middleware: `Host` allowlist (defeats DNS rebinding), `Origin` allowlist when present, `x-requested-by: netwatcher` header on state changes.
- SSE endpoint is GET-only and read-only — the `Host` / `Origin` gate still applies, but the CSRF header is skipped because `EventSource` can't set custom headers.
- All shell calls use argv-form `execFile` / `spawn` — no `sh -c`. IPs go through `net.isIP()`; loopback / unspecified rejected.
- PID ownership compared by numeric uid (avoids `ps` username truncation).
- Frontend escapes every server-supplied string before `innerHTML`.
- Sudo password (when used) is sent only to localhost, never logged or persisted.

## External services

| Service | Purpose | Cost |
| --- | --- | --- |
| ip-api.com | Batch geo lookup | Free, 45 req/min, no key |
| api.ipify.org | Public IP | Free, no key |
| VirusTotal *(optional)* | IP reputation via `vt` CLI | Your own key (`vt init`) |

No frontend CDN. `public/` loads only its own `app.js` / `style.css` + Google Fonts (Manrope, JetBrains Mono).

## macOS pf notes

macOS ships a **frozen, OpenBSD ~4.5-era** copy of pf. The rule syntax has moved on upstream; NetWatcher writes for the macOS dialect.

| macOS | pf base | Key consequence |
| --- | --- | --- |
| 10.7 → 10.10 | OpenBSD ~4.3 – 4.5 | First pf on macOS; Apple-only `pfctl -E` / `-X` (refcounted enable). |
| 10.11 → 10.15 | ~4.5 + back-ports | Pre-4.7 NAT/rdr syntax, no `match` keyword. |
| 11 → 14 | Same line | No re-import; `/etc/pf.conf` rewritten by OS updates. |

NetWatcher's anchor:
```
table <netwatcher_block> persist
block drop out quick from any to <netwatcher_block>
block drop in  quick from <netwatcher_block> to any
```

Loaded at runtime via `pfctl -a com.apple/250.netwatcher -f -`. The anchor path matters: macOS' main ruleset references `anchor "com.apple/*"` but nothing else, so a bare top-level anchor like `netwatcher` is loaded but never evaluated — every packet sails past it. Nesting under `com.apple/` makes the wildcard recurse into our rules. The `250.` prefix keeps us clear of Apple's own `com.apple.<feature>` anchors and pins evaluation order.

Why this rule shape: explicit `in` / `out` (macOS pf rejects direction-less rules with `syntax error` on some hosts), no `match` / `nat-to` / `rdr-to` (4.7+ only).

Blocking an IP also runs `pfctl -k <ip>` immediately after adding it to the table. pf tracks established flows in a state table with a cached `pass` verdict; without killing matching states, a download in progress keeps flowing because its packets never re-enter rule evaluation. Killing states forces the next packet through the rules, where the new block fires.

References: [PF on Mac OS X](https://manjusri.ucsc.edu/2015/03/10/PF-on-Mac-OS-X/) · [Apple's PF import history](https://callfortesting.org/macpf/) · [macOS pf setup guide](https://iyanmv.medium.com/setting-up-correctly-packet-filter-pf-firewall-on-any-macos-from-sierra-to-big-sur-47e70e062a0e) · [pf.conf(5)](https://man.openbsd.org/pf.conf) · [PF anchors](https://www.openbsd.org/faq/pf/anchors.html) · [pfctl(8)](https://man.openbsd.org/pfctl)

## Limitations

- macOS only — `lsof`, `nettop`, and `pfctl` dependent.
- `lsof` without sudo sees only your user's sockets (intentional).
- Per-process attribution; not per-tab / URL.
- `process-info.ts` is a hand-maintained list of ~160 common macOS processes.
- **UDP unconnected sockets are intentionally not shown** — `lsof` reports them as `UDP *:port` with no remote, so there's nothing to geo-locate or block. For per-process byte-level visibility (what Activity Monitor's Network tab uses), see `nettop -P -t external`.

## License

MIT
