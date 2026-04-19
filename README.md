# NetWatcher

A local network-connection dashboard for macOS. Shows every outbound connection on your machine grouped by process, enriched with geolocation, reverse DNS, and process metadata, plotted on a 3D globe. Lets you kill processes and block remote IPs via `pfctl` without leaving the browser.

![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![node](https://img.shields.io/badge/node-%3E%3D20-green)

## What it does

- **Live connection list** — polls `lsof` every 2s, groups by PID, sorts by connection count.
- **Geolocation + reverse DNS** — batch-looks up remote IPs against ip-api.com; caches results.
- **3D globe** — home location + remote endpoints as pins, arcs between them, hover to highlight.
- **Kill a process** — verifies PID ownership (same uid), sends SIGTERM.
- **Block an IP** — adds it to a dedicated `pfctl` anchor/table (no root needed after a one-time sudoers entry).
- **VirusTotal lookup** — optional; uses the `vt` CLI if installed.

Everything runs locally — the server binds to `127.0.0.1:3847` and validates both `Host` and a custom CSRF header to defeat DNS rebinding.

## Install

Requires macOS, Node.js ≥ 20, and `sudo`. Prerequisites are listed in `requirements.txt`.

```bash
./setup.sh
```

The script verifies tools, enables `pnpm` via corepack, installs deps, typechecks, and prints the sudoers hint for `pfctl` if passwordless sudo isn't configured yet.

## Run

```bash
pnpm dev          # http://localhost:3847 (auto-restart via tsx watch)
pnpm build        # compile to dist/
pnpm start        # run the compiled build
pnpm typecheck    # tsc --noEmit
```

## Enabling the Block / Unblock buttons

`/api/block` and `/api/unblock` shell out to `sudo /sbin/pfctl`. For interactive use, add a scoped sudoers entry:

```bash
sudo visudo -f /etc/sudoers.d/netwatcher
```

```
Cmnd_Alias NETWATCHER_PFCTL = /sbin/pfctl -a netwatcher *, /sbin/pfctl -e
YOUR_USERNAME  ALL=(root) NOPASSWD: NETWATCHER_PFCTL
```

Without this, the buttons will return an askpass error. The `Cmnd_Alias` pins sudo to the `netwatcher` anchor so a compromised server cannot flush all pf rules or load an arbitrary config.

## Architecture

```
src/
├── index.ts           # Express app + Host/Origin/CSRF middleware
├── routes.ts          # REST API (/api/connections, /kill, /block, /unblock, /vt, /host-info)
├── connections.ts     # lsof -F parser (machine-readable, IPv6-aware)
├── geolocation.ts     # ip-api.com batch client + 24h cache
├── dns-resolver.ts    # dns/promises.reverse() + 30min cache
├── process-info.ts    # static knowledge base of common macOS processes
├── process-kill.ts    # uid-verified SIGTERM
├── firewall.ts        # pfctl anchor / table management
└── virustotal.ts      # `vt ip <ip>` CLI wrapper

public/
├── index.html         # no build step — loaded as-is
├── app.js             # polls API, renders cards + globe
└── style.css
```

## Security posture

- Server binds to `127.0.0.1` only; startup aborts if the bound address is anything else.
- `/api` middleware enforces a `Host` header allowlist (defeats DNS rebinding), an `Origin` allowlist (when present), and a custom `x-requested-by: netwatcher` header for every state-changing request.
- All shell calls use argv-form `execFile`/`spawn` — no `sh -c`. IPs are validated with `net.isIP()` before reaching `pfctl`; loopback and unspecified addresses are rejected to prevent self-lockout.
- PID ownership is compared by numeric uid (not username) to avoid `ps` truncation false-matches.
- The frontend escapes every server-supplied string rendered via `innerHTML`.

## External services

| Service | Purpose | Cost |
| --- | --- | --- |
| ip-api.com | Batch geo lookup | Free tier, 45 req/min, no key |
| api.ipify.org | Public-IP detection | Free, no key |
| unpkg.com / jsdelivr | globe.gl + Three.js CDN | Loaded by the browser |
| VirusTotal (optional) | IP reputation via `vt` CLI | Requires your own API key (`vt init`) |

## Limitations

- macOS only — depends on `lsof` output format and `pfctl`.
- `lsof` without sudo only sees the current user's sockets. This is intentional.
- Connection attribution is per-process, not per-tab/URL — the OS doesn't expose which browser tab opened which socket.
- `process-info.ts` is a hand-maintained list of ~160 common macOS process names.

## License

MIT
