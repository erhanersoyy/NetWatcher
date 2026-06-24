/* ============================================================
   NetWatcher — wiring real API to the Radar Room redesign
   ============================================================ */

import { escapeHtml, isIPv6, isLocalhost, isPrivateIP, flag, formatBytes, fmtBytes, relTime } from './util.js';
import { el } from './dom.js';
import { S, emit, on } from './state.js';
import { fetchConnections, fetchHostInfo, fetchBlockedIPs } from './api.js';
import { initRadar, prefersReducedMotion, resetLastT } from './radar.js';
import { pushThroughput, initPanels } from './panels.js';
import { initBlockedPanel } from './modals.js';
import { blockIPAction, unblockIPAction, killProcessAction, vtCheckAction, initActions } from './actions.js';

// ---------- DOM ----------
const {
  queueEl, qEl, sortSelect, chipsEl, statusText,
  qToggleBtn, qToggleIcon, refreshSelect, refreshNowBtn,
  dProc, dProcSys, dProcUsr, dConn, dConnSub, dCtry, dCtrySub,
  talkersListEl,
  footRefresh, footSort,
} = el;

// ---------- State ----------
// Reassigned values stay as S.x — ES module live-bindings are read-only to
// importers, so cross-module writes must mutate the shared S object.
// Mutated-in-place values (never reassigned) are aliased locally for brevity.
const liveTraffic  = S.liveTraffic;   // Map — only .set/.delete/.get, never =
const expandedPids = S.expandedPids;  // Set — only .add/.delete/.has, never =
const filter = S.filter;              // object — only .prop = val, never =

const prevConnBytes = new Map();      // connId -> bytes (render-local, not cross-module)

// ---------- Helpers (pure fns imported from util.js) ----------
// The server now stamps each EnrichedConnection with its canonical `trafficKey`
// (matches SSE delta keys exactly). We used to recompute the key client-side
// for every conn × every render; deleted. `conn.trafficKey` is always present
// from `/api/connections`.

// ---------- Sort / filter ----------
function sortProcesses(processes) {
  const mode = sortSelect.value;
  return [...processes].sort((a, b) => {
    if (mode === 'pid') return a.pid - b.pid;
    if (mode === 'name') return a.processName.localeCompare(b.processName);
    return b.connections.length - a.connections.length;
  });
}

function applyFilters(processes) {
  const search = filter.q.toLowerCase().trim();
  return processes
    .filter(proc => !(filter.sys && proc.isSystemProcess))
    .map(proc => {
      const filtered = proc.connections.filter(conn => {
        if (filter.v6 && isIPv6(conn.remoteAddress)) return false;
        if (filter.priv && isPrivateIP(conn.remoteAddress)) return false;
        if (search) {
          const hay = `${proc.processName} ${conn.remoteAddress} ${conn.domain || ''} ${conn.geo?.country || ''} ${conn.geo?.isp || ''} ${conn.geo?.city || ''}`.toLowerCase();
          if (!hay.includes(search)) return false;
        }
        return true;
      });
      return { ...proc, connections: filtered };
    })
    .filter(proc => proc.connections.length > 0);
}

// ---------- Process aggregation (for the row meta line) ----------
function procSummary(proc) {
  const countries = new Map();
  let totalBytes = 0;
  for (const c of proc.connections) {
    const cc = c.geo?.countryCode;
    if (cc) countries.set(cc, (countries.get(cc) || 0) + 1);
    const live = liveTraffic.get(c.trafficKey);
    totalBytes += (live ? live.bytesIn : (c.bytesIn || 0));
    totalBytes += (live ? live.bytesOut : (c.bytesOut || 0));
  }
  // pick the most-represented country as the row's primary origin
  let primary = null;
  let best = 0;
  for (const [cc, n] of countries) {
    if (n > best) { best = n; primary = cc; }
  }
  return { primaryCC: primary, totalBytes, countryCount: countries.size };
}

// ---------- Render ----------
function updateExpandToggle(visible) {
  const btn = document.getElementById('expandToggleChip');
  if (!btn || !S.lastData) return;
  // `visible` is passed in by `renderQueue` to avoid a second applyFilters
  // pass. Chip-click path computes its own (rare, on user interaction).
  if (!visible) visible = applyFilters(S.lastData);
  const allOpen = visible.length > 0 && visible.every((p) => expandedPids.has(p.pid));
  btn.classList.toggle('all-expanded', allOpen);
  const lbl = btn.querySelector('.lbl');
  if (lbl) lbl.textContent = allOpen ? 'collapse all' : 'expand all';
  btn.title = allOpen ? 'Collapse all' : 'Expand all';
}

// Signature over the inputs that renderQueue actually reads. Guards against
// the wholesale `innerHTML` rewrite when nothing visible has changed (e.g.
// poll returned identical data, no filter/sort/expand state changed). SSE
// delta patching still updates bytes in place under this guard.
function computeRenderSig() {
  if (!S.lastData) return '';
  const sort = sortSelect.value;
  const exp = [...expandedPids].sort((a, b) => a - b).join(',');
  const filt = `${filter.sys ? 1 : 0}${filter.v6 ? 1 : 0}${filter.priv ? 1 : 0}|${filter.q}`;
  // Include the full sorted blocked-IP list: per-row "BLOCKED" tag and
  // Block/Unblock button depend on membership, not just set size, so a
  // swap of one IP for another at the same size must invalidate the sig.
  const blocked = [...S.blockedIPs].sort().join(',');
  // Data fingerprint: PID + conn count + remote IPs + states. Byte counts
  // are deliberately excluded — they churn every poll but SSE patches them
  // in place; re-rendering the whole list just to refresh bytes is exactly
  // the waste we're trying to skip.
  const dataParts = [];
  for (const p of S.lastData) {
    dataParts.push(`${p.pid}:${p.connections.length}`);
    for (const c of p.connections) {
      dataParts.push(`${c.remoteAddress}:${c.remotePort}:${c.state}`);
    }
  }
  return `${sort}|${exp}|${filt}|${blocked}|${dataParts.join(';')}`;
}

function renderQueue(force = false) {
  if (!S.lastData) {
    queueEl.innerHTML = '<div class="queue-empty">Loading connections…</div>';
    S.lastRenderSig = '';
    return;
  }
  if (!force) {
    const sig = computeRenderSig();
    if (sig === S.lastRenderSig) return;
    S.lastRenderSig = sig;
  } else {
    S.lastRenderSig = computeRenderSig();
  }
  const filtered = applyFilters(S.lastData);
  const sorted = sortProcesses(filtered);

  updateExpandToggle(sorted);

  if (sorted.length === 0) {
    queueEl.innerHTML = renderQueueEmpty();
  } else {
    queueEl.innerHTML = sorted.map((p, i) => renderProcRow(p, i)).join('');
    flashNewRows(sorted);
  }
  // Remember PIDs from the full dataset (not just the filtered view) so the
  // next render flashes only genuinely-new connections — not rows merely
  // revealed by toggling a filter or clearing the search.
  S.prevPids = new Set((S.lastData || []).map((p) => p.pid));
  S.prevConnKeys = new Set((S.lastData || []).flatMap((p) => p.connections.map((c) => `${p.pid}|${c.remoteAddress}`)));

  // update stats strip
  const totalConns = sorted.reduce((s, p) => s + p.connections.length, 0);
  const countries = new Set();
  const asns = new Set();
  let established = 0, timewait = 0, other = 0;
  for (const p of sorted) {
    for (const c of p.connections) {
      if (c.geo?.countryCode) countries.add(c.geo.countryCode);
      if (c.geo?.isp) asns.add(c.geo.isp);
      const st = (c.state || '').toUpperCase();
      if (st.startsWith('EST')) established++;
      else if (st.includes('TIME')) timewait++;
      else other++;
    }
  }
  dProc.textContent = sorted.length;
  const sysCount = (S.lastData || []).filter(p => p.isSystemProcess).length;
  dProcSys.textContent = sysCount;
  dProcUsr.textContent = (S.lastData || []).length - sysCount;
  dConn.textContent = totalConns;
  dConnSub.textContent = `${established} EST · ${timewait} TIME_WAIT · ${other} other`;
  dCtry.textContent = countries.size;
  dCtrySub.textContent = `across ${asns.size} ASN range${asns.size === 1 ? '' : 's'}`;

  updateChipCounts(filtered.length); // reuse the visible count we already computed
  renderTopTalkers(sorted);
}

// Add the existing `.flash` class (flashFx keyframe) to rows whose PID wasn't
// in the previous render. Skipped under prefers-reduced-motion and on the very
// first render (prevPids === null) so we don't flash the whole list on load.
function flashNewRows(sorted) {
  if (S.prevPids === null || prefersReducedMotion()) return;
  for (const p of sorted) {
    // Flash a row when the process is new OR it reached a NEW remote address
    // (a new outbound connection is the event a security monitor must surface).
    // Keyed by pid+remoteAddress so ephemeral local-port churn doesn't flash.
    const isNewProcess = !S.prevPids.has(p.pid);
    const hasNewRemote = p.connections.some((c) => !S.prevConnKeys.has(`${p.pid}|${c.remoteAddress}`));
    if (!isNewProcess && !hasNewRemote) continue;
    const row = queueEl.querySelector(`.row[data-pid="${CSS.escape(String(p.pid))}"] .pname`);
    if (row) row.classList.add('flash');
  }
}

// How many rows each filter is *currently* hiding, so the chips can show a
// "(N)" badge. Each count re-runs applyFilters with that one toggle forced off,
// holding the other toggles + search as-is; the delta in visible processes is
// what that filter alone is removing. Cheap (lastData is small) and only on render.
function hiddenCounts(baseCount) {
  if (!S.lastData) return { sys: 0, v6: 0, priv: 0 };
  // Reuse renderQueue's already-computed visible count when provided, so we
  // don't run a redundant applyFilters pass every poll.
  const base = baseCount ?? applyFilters(S.lastData).length;
  const without = (key) => {
    const saved = filter[key];
    filter[key] = false;
    const n = applyFilters(S.lastData).length;
    filter[key] = saved;
    return Math.max(0, n - base);
  };
  return {
    sys: filter.sys ? without('sys') : 0,
    v6: filter.v6 ? without('v6') : 0,
    priv: filter.priv ? without('priv') : 0,
  };
}

function updateChipCounts(baseCount) {
  const counts = hiddenCounts(baseCount);
  for (const key of ['sys', 'v6', 'priv']) {
    const chip = chipsEl.querySelector(`.chip[data-f="${key}"]`);
    if (!chip) continue;
    let badge = chip.querySelector('.count');
    const n = filter[key] ? counts[key] : 0;
    if (n > 0) {
      if (!badge) { badge = document.createElement('span'); badge.className = 'count'; chip.appendChild(badge); }
      badge.textContent = n;
    } else if (badge) {
      badge.remove();
    }
  }
}

// Empty-state markup. The three default-on filters can hide every row, which
// reads as "nothing is connecting" — offer a one-click reset so the user can
// tell the difference. The Clear button only appears when a filter is actually
// active (otherwise the list is genuinely empty).
function renderQueueEmpty() {
  const anyFilterOn = filter.sys || filter.v6 || filter.priv || filter.q;
  const clearBtn = anyFilterOn
    ? '<div><button class="queue-clear-filters" data-action="clear-filters">Clear filters</button></div>'
    : '';
  const msg = anyFilterOn ? 'No connections match current filters' : 'No connections';
  return `<div class="queue-empty">${msg}${clearBtn}</div>`;
}

function renderProcRow(proc, i) {
  const expanded = expandedPids.has(proc.pid);
  const summary = procSummary(proc);
  const idx = String(i + 1).padStart(2, '0');
  const w = Math.min(1, Math.max(0.08, proc.connections.length / 16)).toFixed(2);
  const f = summary.primaryCC ? flag(summary.primaryCC) : '';
  const countryLabel = summary.primaryCC
    ? `${f} ${summary.primaryCC}${summary.countryCount > 1 ? ` +${summary.countryCount - 1}` : ''}`
    : '· local';
  const traffic = summary.totalBytes > 0 ? `↓↑ ${formatBytes(summary.totalBytes)}` : '';
  const killBtn = `<button class="kill ${proc.isSystemProcess ? 'danger' : ''}" data-action="kill" data-pid="${proc.pid}" data-name="${escapeHtml(proc.processName)}" data-system="${proc.isSystemProcess ? '1' : '0'}" title="Kill PID ${proc.pid}">kill</button>`;

  const rowHtml = `
    <div class="row ${proc.isSystemProcess ? 'sys' : ''} ${expanded ? 'active' : ''}" data-action="toggle" data-pid="${proc.pid}" tabindex="0" role="button" aria-expanded="${expanded}">
      <div class="idx">${idx}</div>
      <div class="name"><span class="pname" title="${escapeHtml(proc.description || proc.processName)}">${escapeHtml(proc.processName)}</span>${killBtn}</div>
      <div class="n">
        <span>${proc.connections.length}</span>
        <span class="bar"><span style="transform:scaleX(${w})"></span></span>
      </div>
      <div class="meta">
        <span>pid ${proc.pid}</span>
        <span class="sep">·</span>
        <span>${countryLabel}</span>
        ${traffic ? `<span class="sep">·</span><span>${traffic}</span>` : ''}
      </div>
    </div>
  `;

  if (!expanded) return rowHtml;
  return rowHtml + renderConnBlock(proc);
}

function renderConnBlock(proc) {
  const rows = proc.connections.map(conn => {
    const geo = conn.geo;
    const f = flag(geo?.countryCode);
    const countryLabel = geo
      ? `${f}${geo.city ? ' ' + escapeHtml(geo.city) + ', ' : ' '}${escapeHtml(geo.country || '')}`
      : 'resolving…';
    const ispLabel = geo?.isp ? `<span class="isp" title="${escapeHtml(geo.isp)}">${escapeHtml(geo.isp)}</span>` : '';

    const dom = conn.domain && conn.domain !== '-'
      ? `<span class="dom">${escapeHtml(conn.domain)}</span>`
      : '';

    const tKey = conn.trafficKey;
    const live = liveTraffic.get(tKey);
    const rx = live ? live.bytesIn : conn.bytesIn;
    const tx = live ? live.bytesOut : conn.bytesOut;

    const canFirewall = !isPrivateIP(conn.remoteAddress) && !isLocalhost(conn.remoteAddress);
    const blocked = S.blockedIPs.has(conn.remoteAddress);
    const acts = [];
    if (canFirewall) {
      acts.push(`<button class="vt" data-action="vt" data-ip="${escapeHtml(conn.remoteAddress)}" title="VirusTotal lookup">VT</button>`);
      if (blocked) {
        acts.push(`<button class="unblock" data-action="unblock" data-ip="${escapeHtml(conn.remoteAddress)}" title="Remove from pf block table">Unblock</button>`);
      } else {
        acts.push(`<button class="block" data-action="block" data-ip="${escapeHtml(conn.remoteAddress)}" title="Add to pf block table">Block</button>`);
      }
    }
    const blockedTag = blocked ? '<span class="blocked-tag">BLOCKED</span>' : '';

    return `
      <div class="c" data-ip="${escapeHtml(conn.remoteAddress)}" data-traffic-key="${escapeHtml(tKey)}">
        <span class="ip"><span class="proto">${escapeHtml(conn.protocol || '')}</span><b>${escapeHtml(conn.remoteAddress)}</b><span class="port">:${conn.remotePort}</span>${dom}</span>
        <span class="meta">
          <span>${countryLabel}</span>
          ${ispLabel}
          <span class="rx" data-role="rx">↓${formatBytes(rx)}</span>
          <span class="tx" data-role="tx">↑${formatBytes(tx)}</span>
          ${blockedTag}
        </span>
        <span class="acts">${acts.join('')}</span>
      </div>
    `;
  }).join('');

  return `<div class="conn">${rows}</div>`;
}

// ---------- Top talkers ----------
function renderTopTalkers(sorted) {
  // Aggregate cumulative bytes per country from currently visible conns.
  const byCountry = new Map();
  for (const p of sorted) {
    for (const c of p.connections) {
      if (!c.geo) continue;
      const key = c.geo.country || c.geo.countryCode || '?';
      const live = liveTraffic.get(c.trafficKey);
      const b = (live ? live.bytesIn : (c.bytesIn || 0)) + (live ? live.bytesOut : (c.bytesOut || 0));
      byCountry.set(key, (byCountry.get(key) || 0) + b);
    }
  }
  const entries = [...byCountry.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (entries.length === 0) {
    talkersListEl.innerHTML = '<div class="line"><span class="k">— no traffic —</span><span class="v"></span></div>';
    return;
  }
  talkersListEl.innerHTML = entries.map(([country, bytes]) =>
    `<div class="line"><span class="k">${escapeHtml(country)}</span><span class="v hot">${escapeHtml(formatBytes(bytes))}</span></div>`,
  ).join('');
}

// ---------- Queue events ----------
queueEl.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const action = el.dataset.action;
  if (action === 'toggle') {
    // Avoid toggling when clicking the inline kill button or anything inside the expanded conn block.
    if (e.target.closest('.conn')) return;
    const pid = Number(el.dataset.pid);
    if (expandedPids.has(pid)) expandedPids.delete(pid);
    else expandedPids.add(pid);
    renderQueue();
    return;
  }
  if (action === 'clear-filters') {
    clearFilters();
    return;
  }
  if (action === 'retry-connections') {
    fetchConnections();
    return;
  }
  e.stopPropagation();
  if (action === 'kill') {
    killProcessAction(Number(el.dataset.pid), el.dataset.name, el.dataset.system === '1', el);
  } else if (action === 'vt') {
    vtCheckAction(el.dataset.ip, el);
  } else if (action === 'block') {
    blockIPAction(el.dataset.ip, el);
  } else if (action === 'unblock') {
    unblockIPAction(el.dataset.ip, el);
  }
});

// Keyboard activation for process rows (Enter/Space), mirroring the click toggle.
queueEl.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const row = e.target.closest?.('.row[data-action="toggle"]');
  if (!row) return;
  e.preventDefault();            // Space must not scroll the page
  const pid = row.dataset.pid;
  row.click();                   // toggles + synchronously re-renders the list
  // renderQueue() rebuilt the list and destroyed the focused row — restore
  // focus to the same process row so keyboard navigation keeps its place.
  queueEl.querySelector(`.row[data-pid="${CSS.escape(pid)}"]`)?.focus();
});

// ---------- Search / sort / chips ----------
let searchTimer;
qEl.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    filter.q = qEl.value;
    renderQueue();
  }, 150);
});

sortSelect.addEventListener('change', () => {
  footSort.textContent = sortSelect.value;
  renderQueue();
});

chipsEl.addEventListener('click', (e) => {
  const b = e.target.closest('.chip');
  if (!b) return;
  const f = b.dataset.f;
  if (f === 'expandToggle') {
    if (!S.lastData) return;
    const visible = applyFilters(S.lastData);
    const allOpen = visible.length > 0 && visible.every((p) => expandedPids.has(p.pid));
    if (allOpen) {
      expandedPids.clear();
    } else {
      for (const p of visible) expandedPids.add(p.pid);
    }
    renderQueue();
    updateExpandToggle();
    return;
  }
  b.classList.toggle('on');
  if (f in filter) filter[f] = b.classList.contains('on');
  renderQueue();
});

// Reset the three filter toggles + search to "show everything". Used by the
// Clear-filters button in the empty state. Syncs the chip `.on` classes and the
// search box so the UI stays consistent with the filter object.
function clearFilters() {
  filter.sys = false;
  filter.v6 = false;
  filter.priv = false;
  filter.q = '';
  for (const key of ['sys', 'v6', 'priv']) {
    chipsEl.querySelector(`.chip[data-f="${key}"]`)?.classList.remove('on');
  }
  qEl.value = '';
  renderQueue();
}

// Queue collapse
qToggleBtn.addEventListener('click', () => {
  document.body.classList.toggle('queue-collapsed');
  const collapsed = document.body.classList.contains('queue-collapsed');
  qToggleBtn.title = collapsed ? 'Expand process list' : 'Collapse process list';
  qToggleIcon.setAttribute('d', collapsed ? 'M6 4 L11 8 L6 12' : 'M10 4 L5 8 L10 12');
  window.dispatchEvent(new Event('resize'));
});

// Keyboard
document.addEventListener('keydown', (e) => {
  const tag = document.activeElement?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA') return;
  if (e.key === '/') { e.preventDefault(); qEl.focus(); }
  else if (e.key.toLowerCase() === 't') {
    document.body.classList.toggle('tweaks-on');
  }
});

// ---------- Firewall / VT / Kill ----------
// (lockBtn, blockIPAction, unblockIPAction, killProcessAction, doKill,
//  vtCheckAction, blockIPManualAction, unblockBulkAction,
//  showBlockedListModal, renderBlockedListBody, wireBlockedToolbar,
//  buildBlockedRows — all moved to actions.js)

// ---------- SSE: live traffic ----------
function connectTrafficStream() {
  let es;
  try { es = new EventSource('/api/traffic-stream'); }
  catch (err) { console.warn('[traffic] EventSource unsupported', err); return; }

  es.addEventListener('delta', (ev) => {
    let arr;
    try { arr = JSON.parse(ev.data); } catch { return; }
    if (!Array.isArray(arr)) return;

    S.streamHealthy = true;
    S.lastDeltaAt = Date.now();

    let rxBytesPerSec = 0, txBytesPerSec = 0;
    for (const e of arr) {
      if (!e || typeof e.key !== 'string') continue;
      const bytesIn = Number(e.bytesIn) || 0;   // no `| 0` — that truncates to 32-bit signed (wraps past ~2.1 GB)
      const bytesOut = Number(e.bytesOut) || 0;
      const prevBytes = liveTraffic.get(e.key);
      if (prevBytes) {
        // A *decreasing* counter means nettop reset / the 5-tuple was reused:
        // count the fresh absolute value rather than dropping the delta to 0.
        const drx = bytesIn < prevBytes.bytesIn ? bytesIn : bytesIn - prevBytes.bytesIn;
        const dtx = bytesOut < prevBytes.bytesOut ? bytesOut : bytesOut - prevBytes.bytesOut;
        rxBytesPerSec += Math.max(0, drx);
        txBytesPerSec += Math.max(0, dtx);
      }
      liveTraffic.set(e.key, { bytesIn, bytesOut });
      // Patch the row in place if visible.
      const sel = `.c[data-traffic-key="${CSS.escape(e.key)}"]`;
      const row = document.querySelector(sel);
      if (!row) continue;
      const rxEl = row.querySelector('[data-role="rx"]');
      const txEl = row.querySelector('[data-role="tx"]');
      if (rxEl) rxEl.textContent = `↓${formatBytes(bytesIn)}`;
      if (txEl) txEl.textContent = `↑${formatBytes(bytesOut)}`;
    }
    // Push the tick into throughput history. The stream delivers roughly 1/s.
    pushThroughput(rxBytesPerSec, txBytesPerSec);
  });

  es.addEventListener('error', () => {
    // EventSource auto-reconnects, but surface the degraded state meanwhile.
    S.streamHealthy = false;
  });
  es.addEventListener('open', () => { S.streamHealthy = true; });

  // Decay the throughput readout to 0 when no deltas arrive (the server only
  // emits a delta when traffic > 0). Paused while the tab is hidden.
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    if (S.lastDeltaAt && Date.now() - S.lastDeltaAt >= 1500) {
      pushThroughput(0, 0);
      S.lastDeltaAt = Date.now(); // keep ticking 0s while idle, but only once/window
    }
  }, 1000);
}

// ---------- Refresh orchestration ----------
async function refreshAll({ fresh } = { fresh: false }) {
  await Promise.all([fetchConnections(), fetchHostInfo({ fresh }), fetchBlockedIPs()]);
}
function scheduleRefresh() {
  if (S.refreshTimer) { clearInterval(S.refreshTimer); S.refreshTimer = null; }
  if (S.refreshIntervalMs > 0) S.refreshTimer = setInterval(() => refreshAll({ fresh: false }), S.refreshIntervalMs);
}
refreshSelect.addEventListener('change', () => {
  S.refreshIntervalMs = parseInt(refreshSelect.value, 10) || 2000;
  footRefresh.textContent = refreshSelect.options[refreshSelect.selectedIndex].textContent;
  scheduleRefresh();
});
refreshNowBtn.addEventListener('click', async () => {
  refreshNowBtn.classList.add('spinning');
  try { await refreshAll({ fresh: true }); }
  finally { refreshNowBtn.classList.remove('spinning'); }
});

// Initial foot text sync
footRefresh.textContent = refreshSelect.options[refreshSelect.selectedIndex].textContent;
footSort.textContent = sortSelect.value;

// ---------- Bus subscriptions ----------
// api.js emits these events instead of calling render fns directly, breaking
// the circular-import hazard. Once each render fn moves to its own module,
// it subscribes itself and this subscription is deleted.
on('data:changed', () => renderQueue());
// blocked:changed is now owned by modals.js (registered inside initBlockedPanel())
// host:changed is now owned by radar.js (registered inside initRadar())

// ---------- Init ----------
statusText.classList.add('wait');
statusText.textContent = 'connecting…';
initRadar();
initPanels();
initBlockedPanel();
initActions();
connectTrafficStream();
refreshAll({ fresh: true });
scheduleRefresh();
