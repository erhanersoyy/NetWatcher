# Blocked-State Re-apply on Launch — Design

**Date:** 2026-06-25
**Status:** Approved (pending spec review)

## Goal

After a reboot wipes the macOS `pf` ruleset, NetWatcher must detect that the
persisted blocked IPs are no longer enforced and let the user re-apply all of
them with a **single sudo entry** — closing the "I think I'm protected but I'm
not" gap.

## Background / Problem

- Blocked IPs are persisted in `data/blocks.json` (`active` map) by
  `block-store.ts`. This survives anything.
- `pf` rules and tables live in the **kernel**, loaded at runtime via
  `pfctl`. They survive a NetWatcher process restart (kernel state is
  independent of the Node process) but **do not survive a reboot** — macOS
  ships with `pf` disabled at boot, and `ensureAnchor()` re-enables it
  (`pfctl -e`) and reloads the anchor only when the next block/unblock runs.
- Therefore, after a reboot: `blocks.json` still lists the blocked IPs and the
  UI shows them, but `pf` is enforcing nothing. The protection is silently
  gone.

## Constraints (from the existing codebase)

1. **The sudo password is never stored.** It is entered per-action in the UI,
   piped to `sudo -S` / used to prime the sudo timestamp, then discarded
   (`firewall.ts`). The server has no password at startup.
2. Passwordless-sudo was **deliberately removed** earlier
   (commit `699b603`). Re-introducing it is out of scope.
3. The server **cannot read the live `pf` table without a primed sudo
   timestamp** — `getBlockedIPsOrNull()` returns `null` ("unknown") when sudo
   is not primed, which is exactly the post-reboot state.
4. All `pfctl` invocations are argv-form `execFile`/`spawn` (no shell).
5. macOS only.

## Chosen Approach

**In-app banner + one-click re-apply.** (Chosen over a manual terminal script
and over a `launchd` boot agent, because it preserves the per-request-sudo
security model, keeps the user in the loop, and adds the least code.)

Flow: **detect (no sudo) → warn (banner) → re-apply (one sudo entry)**.

### 1. Detect — server-side, no sudo required

Neither the server nor the frontend can read `pf` without primed sudo. The one
reboot signal readable **without root** is the system boot time:
`sysctl -n kern.boottime` (output contains `{ sec = <epoch>, usec = ... } ...`).

Detection uses a **per-IP `appliedBoot` marker**:

- Each active `BlockRecord` records the boot epoch-second in which that IP was
  last added to the `pf` table (`appliedBoot`).
- An IP is **stale** (persisted as blocked but almost certainly not enforced)
  when `record.appliedBoot !== currentBoot`.
- `staleCount = active.filter(r => r.appliedBoot !== currentBoot).length`.

Why per-IP (not a single store-wide `lastAppliedBoot`): a single marker breaks
on two real cases — (a) blocking the very first IP on a fresh boot would look
"never applied" and false-alarm, and (b) blocking a new IP while older blocks
are stale, or a partial re-apply, cannot be represented. The per-IP marker is
the same amount of code and is correct in every case, and it makes `staleCount`
exact (so the banner count is trustworthy).

Marker lifecycle:
- `blockIP` success → the new record's `appliedBoot = currentBoot` (it was just
  added to `pf` in this boot).
- `reapplyBlocks` success (per IP) → that IP's `appliedBoot = currentBoot`.
- Reboot → `currentBoot` changes → every existing record's `appliedBoot` is now
  a previous boot → all stale.
- Server restart, same boot → `appliedBoot === currentBoot` → not stale → no
  banner.
- Legacy records with no `appliedBoot` → `undefined !== currentBoot` → counted
  stale → prompts a re-apply (correct: we cannot prove they are live).
- `currentBoot` unreadable (`getBootId()` → `null`) → `staleCount` forced to
  `0` (no banner) to avoid false alarms; a warning is logged.

### 2. Warn — frontend banner

The `GET /api/block-history` response (already an object `{ active, history }`,
already fetched by the frontend) gains two **additive** fields:
`{ ..., stale: boolean, staleCount: number }`. When `stale` is true, a banner
renders at the top of the blocked panel:

> ⚠️ N blocked IP(s) are not currently enforced (likely after a reboot).
> **[Re-apply all]**

### 3. Re-apply — one sudo entry

Clicking **Re-apply all** opens the **existing** sudo modal. On submit:
`POST /api/reapply` (CSRF-protected, password in JSON body, mirrors
`/api/block/:ip`) →
`validateSudo(password)` once → `ensureAnchor()` → add every active IP to the
`pf` table (`-T add`), best-effort, collecting per-IP failures → mark each
successfully-applied IP's `appliedBoot = currentBoot` → respond
`{ success, applied: string[], failed: { ip, message }[], message }`.

The frontend toasts the result and refetches blocked state; the banner clears
when `staleCount` returns to 0 (i.e., every active IP was applied). On partial
failure only the failed IPs stay stale, so the banner persists with the
accurate remaining count and the toast names the failures.

## Components

### `src/boot-info.ts` (new, ~20 lines)

- `parseBootSec(sysctlOutput: string): number | null` — pure; extracts the
  `sec = <N>` integer from `kern.boottime` output. Exported for unit testing.
- `getBootId(): Promise<number | null>` — `execFile('sysctl', ['-n',
  'kern.boottime'])`, parse via `parseBootSec`, **cache** the result for the
  process lifetime (boot time is constant per OS boot). Returns `null` on
  exec/parse failure. No sudo.

### `src/types.ts`

- `BlockRecord` gains `appliedBoot?: number | null` — boot epoch-second in
  which this IP was last added to `pf`.

### `src/block-store.ts` (~20 lines changed)

- `recordBlock(ip, meta, appliedBoot: number | null)` — gains the `appliedBoot`
  param; stored on the record.
- `markReapplied(ips: string[], bootId: number): Promise<void>` — for each IP
  in `active` that is in `ips`, set `appliedBoot = bootId`. Serialized via the
  existing `serialize()` write-chain.
- `countStaleBlocks(active: BlockRecord[], currentBoot: number): number` —
  pure; `active.filter(r => r.appliedBoot !== currentBoot).length`. Exported
  for unit testing.
- `getBlockHistory()` already returns `active` records, which now carry
  `appliedBoot`.

### `src/firewall.ts` (~35 lines)

- import `getBootId`; import `markReapplied`.
- `blockIP`: after the successful `-T add`, resolve `currentBoot = await
  getBootId()` and pass it into `recordBlock(...)` so the new record's
  `appliedBoot` is set.
- `reapplyBlocks(ips: string[], password: string): Promise<{ success: boolean;
  applied: string[]; failed: { ip: string; message: string }[]; message?:
  string }>`:
  - validate password non-empty; `validateSudo(password)` once.
  - `ensureAnchor()`.
  - `currentBoot = await getBootId()`.
  - for each `ip` (skip non-`isBlockableIP`): `pfctl -a ANCHOR -t TABLE -T add
    ip`; on success push to `applied`, on error push `{ ip, message }` to
    `failed`. (No `pfctl -k` — after a reboot there are no live states to
    kill; this is the primary case.)
  - `markReapplied(applied, currentBoot)` when `currentBoot != null`.
  - `success = failed.length === 0`.

### `src/routes.ts` (~20 lines)

- `GET /api/block-history`: compute `currentBoot = await getBootId()`;
  `staleCount = currentBoot == null ? 0 : countStaleBlocks(data.active,
  currentBoot)`; respond `{ ...data, stale: staleCount > 0, staleCount }`.
- `POST /api/reapply`: read `password` from body (same shape as
  `/api/block/:ip`); `ips = (await getBlockHistory()).active.map(r => r.ip)`;
  `result = await reapplyBlocks(ips, password)`; status
  `result.success ? 200 : 400`.

### Frontend (`public/js/`, ~45 lines)

- `api.js`:
  - `fetchBlockedIPs()` — when parsing `/api/block-history`, also read
    `data.stale` / `data.staleCount` into `S.blocksStale` / `S.staleCount`
    (kept on the shared state object). The existing `blocked:changed` emit
    already drives the panel re-render.
  - add `reapplyBlocks(password)` — `POST /api/reapply` via the existing
    `sendFirewallRequest`-style helper (password zeroed after send).
- `state.js`: add `blocksStale` / `staleCount` fields to `S`.
- `modals.js` `renderBlockedPanel()`: when `S.blocksStale`, prepend a banner
  element (DOM API + `textContent`, no `innerHTML` sink) with the count and a
  `data-action="reapply-blocks"` button.
- `actions.js`: handle `reapply-blocks` → open the existing sudo modal → on
  submit call `api.reapplyBlocks(pw)` under the existing in-flight button lock
  → toast `applied`/`failed` → `fetchBlockedIPs()` to refresh (banner clears
  when `staleCount` hits 0).

## Data Flow

```
reboot → pf wiped, blocks.json intact (appliedBoot = old boot)
  → GET /api/block-history: currentBoot != appliedBoot → stale:true, staleCount:N
    → renderBlockedPanel shows banner
      → user clicks "Re-apply all" → sudo modal → POST /api/reapply {password}
        → validateSudo → ensureAnchor → pfctl -T add (each) → markReapplied(applied, currentBoot)
          → fetchBlockedIPs → staleCount 0 → banner clears
```

## Error Handling / Edge Cases

- **`getBootId()` fails** → `staleCount` forced 0, no banner, warning logged.
  (`sysctl kern.boottime` is world-readable and effectively always succeeds on
  macOS; this is defense-in-depth, not an expected path.)
- **Partial re-apply** → only failed IPs keep their old `appliedBoot`; banner
  persists with the accurate remaining count; toast names the failed IPs.
- **`active` empty** → `staleCount` 0 → no banner ever.
- **Bad sudo password** → `validateSudo` rejects → `reapplyBlocks` returns
  `{ success:false, ... }` → toast shows the auth error; banner stays.
- **Non-blockable IP somehow in the store** (e.g. a loopback that slipped in) →
  skipped during re-apply and reported in `failed`.

## Out of Scope (YAGNI)

- Detecting drift from a **manual `pfctl -F`** without a reboot (boot time is
  unchanged, so the boottime signal misses it). This is a deliberate,
  user-initiated, rare action. The frontend already holds both the live-`pf`
  set (when sudo is primed) and the persisted set, so a future enhancement can
  add a sudo-backed live diff — not built now.
- Reconciling the inverse drift (IPs live in `pf` but absent from the store —
  blocked out-of-band). Pre-existing documented limitation; unchanged.
- Auto-applying at boot (rejected: needs stored password or passwordless sudo).

## Testing

Unit tests (Node's built-in runner, consistent with the existing suite):

- `parseBootSec` — sample `kern.boottime` strings parse to the right epoch
  second; malformed / empty input → `null`.
- `countStaleBlocks` — empty active → 0; all `appliedBoot === currentBoot` →
  0; mixed → exact count; records with `appliedBoot` undefined → counted stale.
- `block-store` round-trip — `recordBlock` persists `appliedBoot`;
  `markReapplied` updates `appliedBoot` only for the named IPs and leaves
  others untouched.

The `pfctl`/sudo path stays integration-only (no unit tests for live `pfctl`),
consistent with the existing `firewall.ts` testing posture.
