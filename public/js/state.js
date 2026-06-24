// ---------- Shared mutable state ----------
// A single object so cross-module writes are visible to all importers.
// ES module live-bindings are read-only to importers — a consumer can't
// reassign an imported `let`. Writers must mutate a property (`S.x = val`).
export const S = {
  lastData:         null,
  hostInfo:         null,
  blockedIPs:       new Set(),
  blockedMeta:      new Map(),   // ip -> { country, countryCode, isp, blockedAt }
  liveTraffic:      new Map(),   // trafficKey -> { bytesIn, bytesOut }
  streamHealthy:    false,
  lastDeltaAt:      0,
  filter:           { sys: true, v6: true, priv: true, q: '' },
  blockedQ:         '',
  expandedPids:     new Set(),
  prevPids:         null,
  prevConnKeys:     null,
  lastRenderSig:    '',
  killsInFlight:    new Set(),
  refreshTimer:     null,
  refreshIntervalMs: 300000,
};

// ---------- EventTarget bus ----------
// Thin wrapper so future modules can emit/subscribe without referencing
// DOM EventTarget directly. No behavior is wired in this task — the bus
// is exported here for later tasks to use.
export const bus = new EventTarget();
export const emit = (name, detail) => bus.dispatchEvent(new CustomEvent(name, { detail }));
export const on   = (name, fn)     => bus.addEventListener(name, (e) => fn(e.detail));

// ---------- CSRF ----------
// All /api/* requests must carry this header — the server enforces it on
// GETs too (except SSE). A non-simple header forces a CORS preflight on
// cross-origin attempts, which the Origin allowlist rejects.
export const CSRF_HEADER = { 'x-requested-by': 'netwatcher' };
