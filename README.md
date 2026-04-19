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

## macOS pf / pfctl version notes

macOS ships a forked, frozen-in-time copy of OpenBSD's Packet Filter. The exact vintage matters because the rule syntax has diverged several times on the OpenBSD side while Apple has only picked up scattered updates. NetWatcher's anchor rules are written for the **macOS dialect**, not modern OpenBSD.

### Which OpenBSD version macOS uses

| macOS release | pf base (approx.) | Notes |
| --- | --- | --- |
| 10.7 Lion (2011) – 10.10 Yosemite | OpenBSD ~4.3 – 4.5 | First appearance of pf on macOS (replacing ipfw). Ships `pfctl` with Apple extensions `-E` / `-X` (reference-counted enable, not present in upstream). |
| 10.11 El Capitan – 10.15 Catalina | OpenBSD ~4.5 (with back-ported fixes) | Still **pre-4.7 NAT/rdr syntax** — `rdr` / `nat` rules, not the modern `match in ... rdr-to …` form. No `match` keyword (introduced upstream in 4.6). |
| 11 Big Sur – 14 Sonoma | Same line | Binary/feature parity with earlier macOS pf; Apple hasn't re-imported from OpenBSD. `/etc/pf.conf` is overwritten on OS updates, so anchor files must live elsewhere. |

In practice every supported macOS (Sierra → Sonoma) exposes roughly the same pf capabilities as **OpenBSD 4.5–4.6**, with Apple-specific reference counting on top.

### Syntax things that differ from modern OpenBSD

- **No `match` rules** (OpenBSD 4.6+). Use plain `block` / `pass` with explicit direction.
- **Old NAT/rdr form only.** `nat-to`, `rdr-to`, `match in … rdr-to …` (OpenBSD 4.7+) are **not** parsed. Use the legacy `nat on $if from … to … -> …` / `rdr on $if …` form.
- **Direction is not always optional.** Modern OpenBSD is forgiving when direction is omitted, but macOS pf often rejects rules like `block drop quick from <table> to any` with `syntax error` unless `in` / `out` is written explicitly.
- **Default state creation & `flags S/SA`.** macOS pf inherits the OpenBSD 4.1+ defaults — filter rules auto-create state; TCP rules default to `flags S/SA`. You don't need `keep state` on simple rules.
- **Tables defined inside an anchor file.** Works on OpenBSD, but is flagged in community guides as *sometimes* breaking pf startup on macOS if the same anchor is loaded at boot from `pf.conf`. NetWatcher sidesteps this by loading the table+rules at runtime via `pfctl -a netwatcher -f -` rather than from `/etc/pf.conf`.
- **Apple-only `pfctl` flags.** `-E` (enable + increment ref count, returns a token) and `-X <token>` (decrement ref count) exist only on macOS. NetWatcher uses plain `-e` for enable and doesn't rely on tokens.
- **Anchor wildcard listing.** `pfctl -s ... -a 'anchor/*'` is buggy on macOS; enumerate by full path instead.

### What NetWatcher's ruleset targets

The anchor loaded at `src/firewall.ts` is written against the macOS dialect above:

```
table <netwatcher_block> persist
block drop out quick from any to <netwatcher_block>
block drop in  quick from <netwatcher_block> to any
```

Why this shape:

- **`table <…> persist`** — classic OpenBSD 4.x syntax, supported on every macOS version that ships pf.
- **Explicit `in` / `out`** — required for reliable parsing on macOS (rules without direction can trigger the `stdin:N: syntax error` from `pfctl -f -` on some hosts).
- **`block drop … quick`** — no `match`, no `set`, no 4.7+ tokens; stays inside the OpenBSD ≤ 4.6 vocabulary macOS understands.
- **Two directions, both via the same table** — catches outbound connection attempts from local processes *and* inbound traffic sourced from a blocked peer, without needing `nat`/`rdr` rules.
- **Loaded at runtime, not from `pf.conf`** — avoids the "table defined in anchor file" boot quirk and survives `/etc/pf.conf` getting rewritten by OS updates.

### References

- [PF on Mac OS X — Thus Spake Manjusri](https://manjusri.ucsc.edu/2015/03/10/PF-on-Mac-OS-X/) — version mapping (OpenBSD 4.5, pre-4.7 NAT syntax), Apple's `-E` / `-X` extensions, anchor wildcard bug.
- [How Apple Treats the Gift of Open Source: The OpenBSD PF Example](https://callfortesting.org/macpf/) — timing of Apple's import (≈ OpenBSD 4.3/4.5, Lion era), missing `match` / `set state-defaults`.
- [Setting up correctly Packet Filter (pf) firewall on any macOS — Iyán](https://iyanmv.medium.com/setting-up-correctly-packet-filter-pf-firewall-on-any-macos-from-sierra-to-big-sur-47e70e062a0e) — anchor / table quirks, `/etc/pf.conf` getting overwritten, boot-time gotchas.
- [pf.conf(5) — OpenBSD manual](https://man.openbsd.org/pf.conf) — canonical OpenBSD syntax, useful as the "what macOS is *not*" reference.
- [OpenBSD PF: Anchors](https://www.openbsd.org/faq/pf/anchors.html) — upstream anchor semantics (inherited by macOS).
- [pfctl(8) — OpenBSD manual](https://man.openbsd.org/pfctl) — canonical flag reference (minus Apple's `-E` / `-X`).

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
