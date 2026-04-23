# NetWatcher

Local network-connection dashboard for macOS. Lists outbound connections grouped by process, enriched with geo / reverse DNS / live traffic, plotted on a 2D radar. Kill processes and block IPs via `pfctl` from the browser.

![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![node](https://img.shields.io/badge/node-%3E%3D20-green)

Runs on `127.0.0.1:3847`.

## Install & run

Requires macOS, Node ≥ 20, `sudo`.

```bash
./setup.sh        # pnpm + deps + typecheck
pnpm dev          # http://localhost:3847
```

Other scripts: `pnpm build`, `pnpm start`, `pnpm typecheck`.

## Features

- Live connection list (`lsof`), grouped by PID, configurable refresh
- Live RX/TX per connection — long-running `nettop` → SSE deltas
- Batched geo + reverse DNS (ip-api.com), in-memory cache
- 2D radar with rotating sweep, pins per remote country
- System health: CPU / memory / temp / load
- Kill process (uid-verified `SIGTERM`)
- Block / unblock IP via `pfctl` — sudo prompted per action, never stored
- Blocked-IPs history with filter / export / bulk unblock
- VirusTotal lookup (optional, via local `vt` CLI)

Keys: `/` focus search, `T` tweaks.

## REST API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/connections` | Connections grouped by PID |
| `GET` | `/api/traffic-stream` | SSE, per-connection RX/TX deltas |
| `GET` | `/api/host-info` | Host + public IP + geo |
| `GET` | `/api/system-health` | CPU / mem / temp / load |
| `POST` | `/api/kill/:pid` | `SIGTERM` |
| `POST` | `/api/block/:ip` | Add to pf table |
| `POST` | `/api/unblock/:ip` | Remove from pf table |
| `GET` | `/api/blocked` | Currently blocked IPs |
| `GET` | `/api/block-history` | Full block history |
| `GET` | `/api/vt/:ip` | VirusTotal lookup |

State-changing calls require header `x-requested-by: netwatcher`. Block / unblock accept a one-time sudo password in the JSON body.

## Security

- Bound to `127.0.0.1` only; aborts otherwise
- `Host` / `Origin` allowlist + CSRF header on state changes
- `execFile` / `spawn` in argv form only — no shell interpolation
- PID ownership verified by numeric uid
- Sudo password sent only to localhost, piped to `sudo -S` over stdin, never logged or stored

## pf anchor

Loaded at runtime under `com.apple/250.netwatcher`:

```
table <netwatcher_block> persist
block drop out quick from any to <netwatcher_block>
block drop in  quick from <netwatcher_block> to any
```

Nested under `com.apple/` because macOS' main ruleset only recurses into that wildcard — a top-level `netwatcher` anchor would be loaded but never evaluated. After each block, `pfctl -k <ip>` kills existing state entries so in-flight flows stop immediately.

macOS pf is frozen at OpenBSD ~4.5 syntax. [macOS pf guide](https://iyanmv.medium.com/setting-up-correctly-packet-filter-pf-firewall-on-any-macos-from-sierra-to-big-sur-47e70e062a0e) · [pf.conf(5)](https://man.openbsd.org/pf.conf)

## Limitations

- macOS only (`lsof`, `nettop`, `pfctl`)
- `lsof` without sudo sees only your user's sockets (intentional)
- Per-process, not per-tab / URL
- UDP unconnected sockets hidden (no remote endpoint to geo-locate)

## License

MIT
