# NetWatcher

Local macOS connection monitor for investigating unwanted traffic and applying IP block rules. Shows readable connected sockets by process, live traffic counters, process identity context and firewall configuration status. It does not automatically classify traffic as malicious.

## Install & run

Requires macOS, Node ≥ 20 and pnpm. Run as your normal user; the web server refuses root execution.

```bash
./setup.sh
pnpm dev
```

Open the **private access link printed in the terminal** (`http://127.0.0.1:3847/#access=…`). The key changes on every server start. It is exchanged for an HttpOnly, SameSite=Strict session cookie and removed from the address bar. Sessions expire after 12 hours or a restart. Keep the link and terminal output private. The bare URL requires an existing session. A port conflict now fails normally instead of killing another program.

Checks: `pnpm typecheck`, `pnpm test`, `pnpm build`. Run the compiled app with `pnpm start`.

## Monitoring & privacy

- Snapshot list from `lsof`, grouped by PID; filters are opt-in.
- Live sampled RX/TX counters from `nettop`, with sampler health separate from an open SSE connection.
- OS-reported executable path, numeric UID, parent PID and start time, with automatic on-disk signature checks and SHA-256 observations. Results appear in the process row and details; no verification button is needed.
- Public IP, approximate IP location/ISP and reverse DNS are enabled automatically. Public IP uses [ipify over HTTPS](https://www.ipify.org/); locations use [ipwho.is over HTTPS](https://ipwhois.io/documentation). This sends public destination IPs to the location provider. PTR queries use Node's configured DNS servers. Local, reserved and invalid addresses are excluded from external lookups.
- Public-IP results are cached for five minutes, geography for 24 hours and PTR records for one hour, in memory only. DNS and geography run in independent bounded queues; a slow provider does not delay the connection list. Each request is limited to four seconds. Negative results retry later; HTTP 429 respects `Retry-After` and pauses geography queries globally. The provider currently documents 1,000 free requests/day; no key or paid subscription is configured.
- The connection map uses locally served MapLibre GL JS and country boundaries. It works without host geography. Clusters and IP selections filter the process list; opening a process highlights and frames its targets. The map retains the search/filter context so another destination remains selectable. Unknown locations have an accessible target list; WebGL failure keeps this list usable. Point size represents sampled upload speed; missing/partial/stale samples display as unavailable. There is no continuous sweep.
- VirusTotal is optional (`vt` CLI), queried only by explicit action. It sends the selected IP to that service. Retrieval time and provider analysis time are separate; zero detections do not prove safety.

Key: `/` searches. The connection map is always enabled. The isolated UI fixture uses synthetic data and simulated mutations: `node scripts/ui-preview.mjs` on port 3857. **Never enter a real password in the fixture.** It does not implement production authentication.

For a read-only UI check with real enrichment of public DNS endpoints, use `node --import tsx scripts/ui-preview.mjs --live-enrichment`. Process/traffic/action data remains synthetic. Map data regressions: `node scripts/radar-check.mjs` (data/atlas tests, not a WebGL benchmark). UI fixture scenarios include missing host/target locations, disabled WebGL, and 100/1,000/10,000 synthetic destinations. The fixture serves the production CSP; browser errors, CSP violations and resource URLs are available at `/__diagnostics`.

## Actions & verification

Connected processes automatically enter a read-only verification queue (two concurrent jobs). NetWatcher runs macOS `codesign --verify --strict` on the resolved executable and reads signing metadata only after successful verification. Valid, ad-hoc, unsigned, invalid and unavailable results are distinct. No executable is launched, no sudo is used, and no reputation upload or notarization lookup is requested by this feature.

Results are shared by executable, cached in memory and invalidated when file identity/size/timestamps change. Unchanged files are rechecked after five minutes; unavailable results retry after one minute while connection polling continues. Commands have eight-second timeouts and jobs a twenty-second deadline. SHA-256 streams files up to 512 MiB; larger files still receive a signature check. The queue and cache are bounded. Closing/restarting the server cancels its checks and clears observations.

The SHA-256 comparison is against the first observation retained in this session, **not a trusted publisher baseline**. Changes may be legitimate updates. Checks concern the on-disk executable's signed content, not a complete recursive app-bundle audit, loaded process memory or scripts run by an interpreter. A valid signature is not a malware verdict or Gatekeeper approval. macOS performs its normal signature trust evaluation; NetWatcher does not force an online notarization check.

Block/unblock/reapply operations are serialized through command execution and saved-state writes. They use argv-based `pfctl` calls, never shell interpolation. Passwords travel over loopback and stdin, not command-line arguments or persistent storage. A fresh `sudo -k -v` check precedes timestamp priming for each operation (subject to local sudo policy).

Rules live in `com.apple/250.netwatcher` / `netwatcher_block`. The main PF rules must reference the anchor; NetWatcher does not rewrite the main ruleset. Blocking/reapplying checks PF enablement, anchor linkage, expected rules and table readback. It clears states originating from the IP and states destined for it, using the appropriate IPv4/IPv6 wildcard. Removing a rule does not enable PF or reload missing rules.

Results distinguish table update, session-state cleanup and persistence; partial failures remain visible. Configuration checks **do not prove that packets were blocked**. Rules apply to all applications communicating with that IP, in both directions. Shared services can be affected. Saved rules may need reapplying after reboot or external PF changes. There is no background privileged service or automatic boot enforcement.

Ending a process rechecks its owner and identity token before sending SIGTERM. PID checks are not atomic with the signal; very fast PID reuse remains a limitation. SIGTERM is not process quarantine.

## API access

All `/api/*` routes, including SSE, require a session cookie. First `POST /api/session` with `Authorization: Bearer <launch key>` and `x-requested-by: netwatcher`; retain the returned cookie. All API calls except SSE also require the custom header. Host and Origin must match `127.0.0.1:3847` or `localhost:3847`; using one host's session on the other will not work. JSON bodies are limited to 8 KiB; compressed bodies are rejected.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/session` | Check session |
| GET | `/api/connections` | Connections and process identities |
| GET | `/api/traffic-stream` | `delta` and `health` SSE events |
| GET | `/api/host-info` | Local interface, hostname, public IP and geography lookup status |
| GET | `/api/system-health` | CPU, memory, temperature, load |
| POST | `/api/kill/:pid` | SIGTERM; JSON `{ "identityToken": "…" }` from the latest snapshot |
| POST | `/api/block/:ip`, `/api/unblock/:ip` | JSON `{ "password": "…" }` |
| POST | `/api/reapply` | Reapply saved rules; JSON password |
| GET | `/api/firewall-status` | PF enablement, anchor/rules, table and errors; nullable unknown states |
| GET | `/api/blocked` | Table IPs or `null`; not proof of enforcement |
| GET | `/api/block-history` | Saved rule state and mutation history |
| DELETE | `/api/block-history/:ip` | Delete inactive history row using `blockedAt` / optional `unblockedAt` |
| GET | `/api/vt/:ip` | Explicit VirusTotal lookup |

## Coverage & trust boundaries

Snapshot sampling can miss brief connections and unconnected UDP. Normal-user collectors do not establish complete system-wide coverage. Endpoint pairs do not prove which side initiated a connection. The sampler stops shortly after its last subscriber disconnects; there is no durable flow history or background threat detection. Byte counters are approximate: shared endpoint tuples may be reported under multiple processes.

Session keys protect against unauthenticated local clients; they do not protect against an attacker controlling the same user account, browser or application files. JSON history is not tamper-evident. It records intended/applied changes but cannot make filesystem writes and kernel operations one crash-atomic transaction.

## License

MIT. Vendored TopoJSON/world-atlas license notices are in `public/vendor/`. MapLibre GL JS 6.16.0 is vendored under BSD-3-Clause in `public/vendor/maplibre-6.16.0/`; its manifest records the npm tarball URL, verified SHA-512 integrity and SHA-256 file hashes. When updating, verify the registry tarball integrity and copy the unmodified module, worker, CSS and license together; update the versioned paths and manifest. No runtime CDN, tile or font service is configured.
