# NetWatcher

A local network-connection dashboard for macOS. Lists every outbound connection on your machine grouped by process, enriched with geo / reverse DNS / process metadata, plotted on a 3D globe. Kill processes and block remote IPs via `pfctl` from the browser.

![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![node](https://img.shields.io/badge/node-%3E%3D20-green)

Everything runs on `127.0.0.1:3847` with `Host`.

## Contents

- [Features](#features)
- [Install & run](#install--run)
- [Block / Unblock setup](#block--unblock-setup)
- [Architecture](#architecture)
- [Security posture](#security-posture)
- [External services](#external-services)
- [macOS pf notes](#macos-pf-notes)
- [Limitations](#limitations)
- [License](#license)

## Features

- **Live connection list** — `lsof` snapshot, grouped by PID, configurable refresh (Live 2s / 5s / 10s / 30s / 1m / 10m + manual).
- **Geo + reverse DNS** — batched against ip-api.com, cached in memory.
- **3D globe** — home + remote endpoints as pins, arcs between them.
- **Kill process** — uid-verified `SIGTERM`.
- **Block / unblock IP** — `pfctl` anchor + table; per-request sudo password (never stored).
- **Blocked IPs history** — persisted to `data/blocks.json` (gitignored), modal shows IP / country / blocked-at / status.
- **VirusTotal lookup** — optional, via the `vt` CLI.

## Install & run

Requires macOS, Node ≥ 20, `sudo`. Prerequisites in `requirements.txt`.

```bash
./setup.sh        # tool check + pnpm + deps + typecheck

pnpm dev          # http://localhost:3847 (tsx watch)
pnpm build        # compile to dist/
pnpm start        # run compiled build
pnpm typecheck    # tsc --noEmit
```

## Block / Unblock setup

Block / Unblock shells out to `sudo /sbin/pfctl`. The UI shows a sudo dialog on every Block / Unblock; the password is sent once to the local server, piped to `sudo -S` over stdin, and never written anywhere. No `NOPASSWD` / sudoers configuration is used or supported.

## Architecture

```
src/
├── index.ts          # Express + Host/Origin/CSRF middleware
├── routes.ts         # REST API
├── connections.ts    # lsof -F parser
├── geolocation.ts    # ip-api.com batch + 24h cache
├── dns-resolver.ts   # reverse DNS + 30min cache
├── process-info.ts   # static process metadata (~160 entries)
├── process-kill.ts   # uid-verified SIGTERM
├── firewall.ts       # pfctl anchor / table mgmt
├── block-store.ts    # data/blocks.json atomic store
└── virustotal.ts     # `vt ip` wrapper

public/
├── index.html        # no build step
├── app.js
└── style.css
```

## Security posture

- Bound to `127.0.0.1` only; aborts if the listener lands elsewhere.
- `/api` middleware: `Host` allowlist (DNS rebinding), `Origin` allowlist when present, `x-requested-by: netwatcher` header on state changes.
- All shell calls use argv-form `execFile` / `spawn` — no `sh -c`. IPs go through `net.isIP()`; loopback / unspecified rejected.
- PID ownership compared by numeric uid (avoids `ps` username truncation).
- Frontend escapes every server-supplied string before `innerHTML`.
- Sudo password (when used) is sent only to localhost, never logged or persisted.

## External services

| Service | Purpose | Cost |
| --- | --- | --- |
| ip-api.com | Batch geo lookup | Free, 45 req/min, no key |
| api.ipify.org | Public IP | Free, no key |
| unpkg / jsdelivr | globe.gl + Three.js CDN | Browser-loaded |
| VirusTotal *(optional)* | IP reputation via `vt` CLI | Your own key (`vt init`) |

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

Why this shape: explicit `in` / `out` (macOS pf rejects direction-less rules with `syntax error` on some hosts), no `match` / `nat-to` / `rdr-to` (4.7+ only), loaded at runtime via `pfctl -a netwatcher -f -` (avoids the "tables defined inside an anchor file" boot quirk and survives OS updates).

References: [PF on Mac OS X](https://manjusri.ucsc.edu/2015/03/10/PF-on-Mac-OS-X/) · [Apple's PF import history](https://callfortesting.org/macpf/) · [macOS pf setup guide](https://iyanmv.medium.com/setting-up-correctly-packet-filter-pf-firewall-on-any-macos-from-sierra-to-big-sur-47e70e062a0e) · [pf.conf(5)](https://man.openbsd.org/pf.conf) · [PF anchors](https://www.openbsd.org/faq/pf/anchors.html) · [pfctl(8)](https://man.openbsd.org/pfctl)

## Limitations

- macOS only — `lsof` and `pfctl` dependent.
- `lsof` without sudo sees only your user's sockets (intentional).
- Per-process attribution; not per-tab/URL.
- `process-info.ts` is a hand-maintained list of ~160 common macOS processes.
- **UDP unconnected sockets are intentionally not shown** — `lsof` reports them as `UDP *:port` with no remote, so there's nothing to geo-locate or block. For per-process byte-level visibility (what Activity Monitor's Network tab uses), see `nettop -P -t external`.

## License

MIT
