/* ============================================================
   NetWatcher — wiring real API to the Radar Room redesign
   ============================================================ */

// ---------- DOM ----------
const queueEl = document.getElementById('queue');
const qEl = document.getElementById('searchInput');
const sortSelect = document.getElementById('sortSelect');
const chipsEl = document.getElementById('chips');
const blockedCountEl = document.getElementById('blockedCount');
const statusText = document.getElementById('statusText');
const qToggleBtn = document.getElementById('qToggle');
const qToggleIcon = document.getElementById('qToggleIcon');
const refreshSelect = document.getElementById('refreshSelect');
const refreshNowBtn = document.getElementById('refreshNowBtn');

// stage/health
const tRx = document.getElementById('tRx');
const tTx = document.getElementById('tTx');
const gRx = document.getElementById('gRx');
const gTx = document.getElementById('gTx');
const dProc = document.getElementById('dProc');
const dProcSys = document.getElementById('dProcSys');
const dProcUsr = document.getElementById('dProcUsr');
const dConn = document.getElementById('dConn');
const dConnSub = document.getElementById('dConnSub');
const dCtry = document.getElementById('dCtry');
const dCtrySub = document.getElementById('dCtrySub');
const talkersListEl = document.getElementById('talkersList');
const hCPU = document.getElementById('hCPU');
const hCPUbar = document.getElementById('hCPUbar');
const hMem = document.getElementById('hMem');
const hMembar = document.getElementById('hMembar');
const hLoad = document.getElementById('hLoad');

// blocked panel
const blockedListEl = document.getElementById('blockedList');
const blockedSearch = document.getElementById('blockedSearch');
const blockedCntBig = document.getElementById('blockedCntBig');
const blockedExport = document.getElementById('blockedExport');
const blockedAdd = document.getElementById('blockedAdd');
const blockedHistoryBtn = document.getElementById('blockedHistory');

// foot
const footRefresh = document.getElementById('footRefresh');
const footSort = document.getElementById('footSort');
const footTz = document.getElementById('footTz');
const footBlocked = document.getElementById('footBlocked');

// masthead
const clockT = document.getElementById('clockT');
const clockD = document.getElementById('clockD');
const hostHostname = document.getElementById('hostHostname');
const hostLocalIP = document.getElementById('hostLocalIP');
const hostPublicIP = document.getElementById('hostPublicIP');
const hostLocation = document.getElementById('hostLocation');
const hostISP = document.getElementById('hostISP');
const queueISP = document.getElementById('queueISP');
const queueGeo = document.getElementById('queueGeo');

// ---------- State ----------
const expandedPids = new Set();
// PIDs present in the previous renderQueue() pass — diffed each render so a
// newly-appearing process can be flashed (a new connection is the most
// important event in a security tool). null until the first render so the
// initial load doesn't flash every row.
let prevPids = null;
let lastData = null;
let hostInfo = null;
let blockedIPs = new Set();
let blockedMeta = new Map(); // ip -> { country, countryCode, isp, blockedAt }
let refreshTimer = null;
let refreshIntervalMs = 300000;
const liveTraffic = new Map();        // trafficKey -> { bytesIn, bytesOut }
let streamHealthy = false;   // true once the SSE stream is delivering deltas
let lastDeltaAt = 0;         // ms timestamp of the last delta (for idle decay)
const prevConnBytes = new Map();      // connId -> bytes
// Filter toggles — mirror the chip states on load.
const filter = { sys: true, v6: true, priv: true, q: '' };
let blockedQ = '';

const CSRF_HEADER = { 'x-requested-by': 'netwatcher' };

// All /api/* requests must carry the CSRF header — the server enforces it
// on GETs too (except SSE). Using a non-simple header forces a CORS
// preflight on cross-origin attempts, which the Origin allowlist rejects.
// EventSource (traffic-stream) cannot use this — it relies on Host/Origin
// allowlist only.
function apiFetch(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: { ...CSRF_HEADER, ...(options.headers || {}) },
  });
}

// ---------- Helpers ----------
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(str) {
  // Regex replace is ~10× faster than creating a <div> per call. Only
  // matters in hot render paths (renderConnBlock runs for every visible
  // conn × 6–8 escapeHtml calls per render).
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}
function isIPv6(addr) { return typeof addr === 'string' && addr.includes(':'); }
function isLocalhost(addr) { return addr === '127.0.0.1' || addr === '::1' || (typeof addr === 'string' && addr.startsWith('127.')); }
function isPrivateIP(addr) {
  if (!addr) return false;
  if (addr.startsWith('10.') || addr.startsWith('192.168.') || addr.startsWith('127.')) return true;
  if (addr === '0.0.0.0' || addr === '::' || addr === '::1' || addr.startsWith('169.254.') || addr.startsWith('fe80:')) return true;
  const lower = addr.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.slice(7);
    if (v4.includes('.')) return isPrivateIP(v4);
  }
  if (addr.startsWith('172.')) {
    const s = parseInt(addr.split('.')[1], 10);
    if (s >= 16 && s <= 31) return true;
  }
  if (addr.startsWith('100.')) {
    const s = parseInt(addr.split('.')[1], 10);
    if (s >= 64 && s <= 127) return true;
  }
  if (/^f[cd][0-9a-f]{2}:/i.test(addr)) return true;
  return false;
}
function flag(code) {
  if (!code || code === 'LO' || code === '??') return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}
function formatBytes(n) {
  if (n === undefined || n === null || isNaN(n)) return '-';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
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
  if (!btn || !lastData) return;
  // `visible` is passed in by `renderQueue` to avoid a second applyFilters
  // pass. Chip-click path computes its own (rare, on user interaction).
  if (!visible) visible = applyFilters(lastData);
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
let lastRenderSig = '';
function computeRenderSig() {
  if (!lastData) return '';
  const sort = sortSelect.value;
  const exp = [...expandedPids].sort((a, b) => a - b).join(',');
  const filt = `${filter.sys ? 1 : 0}${filter.v6 ? 1 : 0}${filter.priv ? 1 : 0}|${filter.q}`;
  // Include the full sorted blocked-IP list: per-row "BLOCKED" tag and
  // Block/Unblock button depend on membership, not just set size, so a
  // swap of one IP for another at the same size must invalidate the sig.
  const blocked = [...blockedIPs].sort().join(',');
  // Data fingerprint: PID + conn count + remote IPs + states. Byte counts
  // are deliberately excluded — they churn every poll but SSE patches them
  // in place; re-rendering the whole list just to refresh bytes is exactly
  // the waste we're trying to skip.
  const dataParts = [];
  for (const p of lastData) {
    dataParts.push(`${p.pid}:${p.connections.length}`);
    for (const c of p.connections) {
      dataParts.push(`${c.remoteAddress}:${c.remotePort}:${c.state}`);
    }
  }
  return `${sort}|${exp}|${filt}|${blocked}|${dataParts.join(';')}`;
}

function renderQueue(force = false) {
  if (!lastData) {
    queueEl.innerHTML = '<div class="queue-empty">Loading connections…</div>';
    lastRenderSig = '';
    return;
  }
  if (!force) {
    const sig = computeRenderSig();
    if (sig === lastRenderSig) return;
    lastRenderSig = sig;
  } else {
    lastRenderSig = computeRenderSig();
  }
  const filtered = applyFilters(lastData);
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
  prevPids = new Set((lastData || []).map((p) => p.pid));

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
  const sysCount = (lastData || []).filter(p => p.isSystemProcess).length;
  dProcSys.textContent = sysCount;
  dProcUsr.textContent = (lastData || []).length - sysCount;
  dConn.textContent = totalConns;
  dConnSub.textContent = `${established} EST · ${timewait} TIME_WAIT · ${other} other`;
  dCtry.textContent = countries.size;
  dCtrySub.textContent = `across ${asns.size} ASN range${asns.size === 1 ? '' : 's'}`;

  updateChipCounts();
  renderTopTalkers(sorted);
  radarUpdateTargets(sorted);
  // Draw one fresh frame for the new targets. No-op while the sweep loop is
  // already running; under reduced-motion (loop stopped) this redraws once so
  // new/closed connection pins still update instead of freezing on stale data.
  scheduleRadarFrame();
}

// Add the existing `.flash` class (flashFx keyframe) to rows whose PID wasn't
// in the previous render. Skipped under prefers-reduced-motion and on the very
// first render (prevPids === null) so we don't flash the whole list on load.
function flashNewRows(sorted) {
  if (prevPids === null || motionQuery?.matches) return;
  for (const p of sorted) {
    if (prevPids.has(p.pid)) continue;
    const row = queueEl.querySelector(`.row[data-pid="${CSS.escape(String(p.pid))}"] .pname`);
    if (row) row.classList.add('flash');
  }
}

// How many rows each filter is *currently* hiding, so the chips can show a
// "(N)" badge. Each count re-runs applyFilters with that one toggle forced off,
// holding the other toggles + search as-is; the delta in visible processes is
// what that filter alone is removing. Cheap (lastData is small) and only on render.
function hiddenCounts() {
  if (!lastData) return { sys: 0, v6: 0, priv: 0 };
  const base = applyFilters(lastData).length;
  const without = (key) => {
    const saved = filter[key];
    filter[key] = false;
    const n = applyFilters(lastData).length;
    filter[key] = saved;
    return Math.max(0, n - base);
  };
  return {
    sys: filter.sys ? without('sys') : 0,
    v6: filter.v6 ? without('v6') : 0,
    priv: filter.priv ? without('priv') : 0,
  };
}

function updateChipCounts() {
  const counts = hiddenCounts();
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
    const blocked = blockedIPs.has(conn.remoteAddress);
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
    if (!lastData) return;
    const visible = applyFilters(lastData);
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

// ---------- Clock ----------
function tickClock() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  clockT.textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  const month = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getMonth()];
  clockD.textContent = `${p(d.getDate())} ${month} ${d.getFullYear()}`;
}
setInterval(tickClock, 1000); tickClock();
footTz.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;

// ---------- API: host info ----------
async function fetchHostInfo({ fresh } = { fresh: false }) {
  try {
    const res = await apiFetch('/api/host-info' + (fresh ? '?fresh=1' : ''));
    if (!res.ok) return;
    hostInfo = await res.json();
    hostHostname.textContent = hostInfo.hostname || '—';
    hostLocalIP.textContent = hostInfo.localIP || '—';
    hostPublicIP.textContent = hostInfo.publicIP || '—';
    if (hostInfo.geo) {
      const f = flag(hostInfo.geo.countryCode);
      const locText = `${hostInfo.geo.city ? hostInfo.geo.city + ', ' : ''}${hostInfo.geo.country || ''}`;
      hostLocation.innerHTML = `${f} ${escapeHtml(hostInfo.geo.city ? hostInfo.geo.city + ', ' : '')}${escapeHtml(hostInfo.geo.country || '')}`;
      hostISP.textContent = hostInfo.geo.isp || '—';
      if (queueISP) queueISP.textContent = hostInfo.geo.isp || '—';
      if (queueGeo) queueGeo.innerHTML = `${f} ${escapeHtml(locText)}`;
      radarSetHome(hostInfo.geo.lat, hostInfo.geo.lon);
    }
  } catch { /* silent */ }
}

// ---------- API: connections ----------
async function fetchConnections() {
  try {
    const res = await apiFetch('/api/connections');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    lastData = data;
    // Prune liveTraffic to the currently-live connections so the Map can't grow
    // unbounded as ephemeral sockets (TIME_WAIT, short UDP, browser conns) churn.
    const liveKeys = new Set();
    for (const p of data) for (const c of p.connections) liveKeys.add(c.trafficKey);
    for (const k of liveTraffic.keys()) if (!liveKeys.has(k)) liveTraffic.delete(k);
    statusText.textContent = streamHealthy ? 'streaming · live' : 'poll · stream offline';
    statusText.classList.toggle('err', !streamHealthy);
    statusText.classList.remove('wait');
    renderQueue();
  } catch (err) {
    statusText.textContent = 'error';
    statusText.classList.add('err');
    // The masthead status is far from the queue; surface the failure inline
    // (with a Retry) so it isn't invisible. Only when we have nothing to show —
    // a transient poll failure shouldn't blow away an already-rendered list.
    if (!lastData) {
      queueEl.innerHTML = `
        <div class="queue-empty queue-error">
          <div>Couldn't load connections — ${escapeHtml(err.message)}</div>
          <div><button class="queue-clear-filters" data-action="retry-connections">Retry</button></div>
        </div>`;
    }
  }
}

// ---------- API: blocked ----------
async function fetchBlockedIPs() {
  let livePfctl = null;  // null = pfctl unreadable (unknown); a Set = authoritative
  try {
    const res = await apiFetch('/api/blocked');
    if (res.ok) {
      const ips = await res.json();
      if (Array.isArray(ips)) livePfctl = new Set(ips);
    }
    // A null body (pfctl unavailable) leaves livePfctl null → unknown below.
  } catch { /* silent → unknown */ }
  // Pull richer metadata (country, blockedAt) from the history endpoint.
  try {
    const res = await apiFetch('/api/block-history');
    if (!res.ok) throw 0;
    const data = await res.json();
    blockedMeta = new Map();
    for (const rec of (data.active || [])) {
      blockedMeta.set(rec.ip, {
        country: rec.country,
        countryCode: rec.countryCode || null,
        isp: rec.isp || null,
        blockedAt: rec.blockedAt,
      });
    }
  } catch { /* silent */ }
  // Display source = the persisted active list (stable: it survives the common
  // case where pfctl is unreadable because the sudo timestamp lapsed ~5 min
  // after the last action), unioned with live pfctl when it IS readable so a
  // block made outside the app still shows. We deliberately do NOT switch
  // sources between polls — that flickered IPs in and out as sudo readability
  // toggled, and made the panel disagree with the history modal.
  // Known limitation: an IP unblocked out-of-band (reboot / external `pfctl -F`)
  // keeps showing until it's unblocked in-app — reconciling that safely needs a
  // feature (re-apply rules on launch), not a guess against an empty snapshot.
  blockedIPs = new Set(livePfctl ?? []);
  for (const ip of blockedMeta.keys()) blockedIPs.add(ip);
  renderBlockedPanel();
  if (blockedCountEl) blockedCountEl.textContent = blockedIPs.size;
  blockedCntBig.textContent = blockedIPs.size;
  footBlocked.textContent = blockedIPs.size;
  if (lastData) renderQueue();
}

function renderBlockedPanel() {
  const ips = [...blockedIPs];
  const q = blockedQ.toLowerCase();
  const filtered = ips.filter(ip => {
    const meta = blockedMeta.get(ip);
    const hay = `${ip} ${meta?.country || ''} ${meta?.isp || ''}`.toLowerCase();
    return !q || hay.includes(q);
  });
  if (filtered.length === 0) {
    blockedListEl.innerHTML = `<div class="blocked-empty">${q ? `No blocked addresses match “${escapeHtml(q)}”` : 'No IPs currently blocked'}</div>`;
    return;
  }
  blockedListEl.innerHTML = filtered.map(ip => {
    const meta = blockedMeta.get(ip) || {};
    const country = meta.country || '';
    const cc = meta.countryCode || '';
    const isp = meta.isp || '';
    const f = flag(cc);
    const when = meta.blockedAt ? relTime(meta.blockedAt) : '—';
    const ccLabel = f ? `${f} ${escapeHtml(country)}` : escapeHtml(country || '—');
    return `
      <div class="blocked-row" data-ip="${escapeHtml(ip)}">
        <span class="ip">${escapeHtml(ip)}</span>
        <span class="cc">${ccLabel}</span>
        <span class="isp" title="${escapeHtml(isp)}">${escapeHtml(isp)}</span>
        <span class="when">${escapeHtml(when)}</span>
        <button class="un" data-action="unblock" data-ip="${escapeHtml(ip)}">Unblock</button>
      </div>
    `;
  }).join('');
}

function relTime(ts) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

blockedSearch.addEventListener('input', () => {
  blockedQ = blockedSearch.value;
  renderBlockedPanel();
});
blockedListEl.addEventListener('click', (e) => {
  const b = e.target.closest('[data-action="unblock"]');
  if (!b) return;
  unblockIPAction(b.dataset.ip);
});
blockedExport.addEventListener('click', () => {
  const rows = [...blockedIPs].map(ip => {
    const m = blockedMeta.get(ip) || {};
    return `${ip},${m.country || ''},${m.blockedAt ? new Date(m.blockedAt).toISOString() : ''}`;
  });
  const csv = 'ip,country,blockedAt\n' + rows.join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'netwatcher-blocked.csv';
  a.click();
});
blockedAdd.addEventListener('click', () => blockIPManualAction());
blockedHistoryBtn.addEventListener('click', () => showBlockedListModal());

// ---------- Firewall / VT / Kill ----------
// Disable a triggering button while its action is in flight so a double-click
// can't fire two requests / open two sudo modals — same disable-then-restore
// pattern as `.blocked-row-remove`. The `:disabled` rule in CSS supplies the
// busy hint. Returns an unlock() that re-enables the button only if it's still
// in the DOM (a renderQueue() rebuild may have replaced it — the isConnected
// guard mirrors `.blocked-row-remove`).
function lockBtn(btn) {
  if (!btn) return () => {};
  btn.disabled = true;
  return () => { if (btn.isConnected) btn.disabled = false; };
}

async function sendFirewallRequest(path, ip, password) {
  let body = JSON.stringify({ password });
  password = '';
  try {
    const res = await apiFetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    body = '';
    return await res.json();
  } finally {
    body = '';
  }
}

function blockIPAction(ip, btn) {
  const unlock = lockBtn(btn);
  askSudoPassword('Block', ip, async (password) => {
    if (!password) { unlock(); return; }
    try {
      const result = await sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password);
      password = '';
      showToast(result.message, result.success ? 'success' : 'error');
      if (result.success) {
        blockedIPs.add(ip);
        await fetchBlockedIPs();
      }
    } catch (err) {
      showToast('Failed to block IP: ' + err.message, 'error');
    } finally {
      unlock();
    }
  });
}
function unblockIPAction(ip, btn) {
  const unlock = lockBtn(btn);
  askSudoPassword('Unblock', ip, async (password) => {
    if (!password) { unlock(); return; }
    try {
      const result = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
      password = '';
      showToast(result.message, result.success ? 'success' : 'error');
      if (result.success) {
        blockedIPs.delete(ip);
        await fetchBlockedIPs();
      }
    } catch (err) {
      showToast('Failed to unblock IP: ' + err.message, 'error');
    } finally {
      unlock();
    }
  });
}

function killProcessAction(pid, name, isSystem, btn) {
  const unlock = lockBtn(btn);
  // System processes get the strong "required for stability" warning; user
  // processes still get a lightweight confirm — killing is irreversible, so it
  // shouldn't be the one action that fires with no confirmation while every
  // (reversible) block pops a sudo modal.
  const message = isSystem
    ? `"${name}" is a system process required for system stability. Are you sure you want to kill it?`
    : `Kill "${name}" (PID ${pid})? This sends SIGTERM and can't be undone.`;
  showConfirmDialog(message, () => doKill(pid, unlock), unlock, isSystem ? 'Kill Anyway' : 'Kill Process');
}
async function doKill(pid, unlock) {
  try {
    const res = await apiFetch(`/api/kill/${pid}`, { method: 'POST' });
    const result = await res.json();
    showToast(result.message, result.success ? 'success' : 'error');
    setTimeout(fetchConnections, 500);
  } catch (err) {
    showToast('Failed to kill process: ' + err.message, 'error');
  } finally {
    if (unlock) unlock();
  }
}

async function vtCheckAction(ip, btn) {
  const unlock = lockBtn(btn);
  showVtModal(ip, 'Loading VirusTotal data…');
  try {
    const res = await apiFetch(`/api/vt/${encodeURIComponent(ip)}`);
    const data = await res.json();
    showVtModal(ip, data.output, data.success);
  } catch (err) {
    showVtModal(ip, 'Failed to reach VT endpoint: ' + err.message, false);
  } finally {
    unlock();
  }
}

// ---------- Modals ----------
function showToast(message, type) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `toast ${type || ''}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// Minimal modal focus management: save the previously-focused element, trap
// Tab within the overlay, and restore focus on close. Returns a cleanup fn.
function trapFocus(overlay) {
  const prev = document.activeElement;
  const sel = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
  const onKey = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...overlay.querySelectorAll(sel)].filter((el) => !el.disabled && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  overlay.addEventListener('keydown', onKey);
  return () => {
    overlay.removeEventListener('keydown', onKey);
    if (prev && typeof prev.focus === 'function') prev.focus();
  };
}

function showConfirmDialog(message, onConfirm, onCancel, confirmLabel = 'Kill Anyway') {
  const existing = document.getElementById('confirmOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'confirmOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="confirm-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">${escapeHtml(message)}</div>
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-kill">${escapeHtml(confirmLabel)}</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  // `dismiss()` is the cancel path (Cancel button, Escape, backdrop) and runs
  // onCancel so a caller can undo any pre-confirm side effect (e.g. an in-flight
  // button lock). The confirm path closes without onCancel — onConfirm owns it.
  const teardown = () => { document.removeEventListener('keydown', onEsc); release(); overlay.remove(); };
  const dismiss = () => { teardown(); if (onCancel) onCancel(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); dismiss(); } }
  document.addEventListener('keydown', onEsc);
  overlay.querySelector('.confirm-cancel').focus(); // safe default focus (avoid the destructive action)
  overlay.querySelector('.confirm-cancel').addEventListener('click', dismiss);
  overlay.querySelector('.confirm-kill').addEventListener('click', () => { teardown(); onConfirm(); });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) dismiss(); });
}

function askSudoPassword(action, ip, onSubmit) {
  const existing = document.getElementById('sudoOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'sudoOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="confirm-dialog sudo-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">
        <div class="sudo-title">sudo operation</div>
        <div class="sudo-body">
          <strong>${escapeHtml(action)}</strong> runs <code>pfctl</code> as root to modify the firewall.<br>
          Target IP: <code>${escapeHtml(ip)}</code>
        </div>
        <div class="sudo-note">Your password is sent once to the local server and <strong>never stored</strong>.</div>
      </div>
      <input type="password" class="sudo-input" placeholder="System password" autocomplete="off" autocapitalize="off" spellcheck="false" />
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-proceed sudo-submit">Proceed</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const input = overlay.querySelector('.sudo-input');
  input.focus();
  const cleanup = (submitted) => {
    let pwd = submitted ? input.value : '';
    input.value = '';
    document.removeEventListener('keydown', onEsc);
    release();
    overlay.remove();
    return pwd;
  };
  // Notify the caller on cancel too (with an empty password) so any pre-modal
  // side effect can be undone — e.g. the in-flight button lock. Every onSubmit
  // already early-returns on a falsy password, so this is a no-op for them.
  const cancel = () => { cleanup(false); onSubmit(''); };
  const submit = () => onSubmit(cleanup(true));
  // Escape closes from anywhere in the dialog (not only while the input is
  // focused), matching the confirm/VT/blocked-list modals.
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); cancel(); } }
  document.addEventListener('keydown', onEsc);
  overlay.querySelector('.confirm-cancel').addEventListener('click', cancel);
  overlay.querySelector('.sudo-submit').addEventListener('click', submit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) cancel(); });
}

function showVtModal(ip, content, success) {
  const existing = document.getElementById('vtOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'vtOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="vt-modal">
      <div class="vt-modal-header">
        <span class="vt-modal-title">VirusTotal · ${escapeHtml(ip)}</span>
        <button class="vt-modal-close">×</button>
      </div>
      <div class="vt-modal-body">${formatVtOutput(content, success)}</div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const close = () => { document.removeEventListener('keydown', onEsc); release(); overlay.remove(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
  document.addEventListener('keydown', onEsc);
  const closeBtn = overlay.querySelector('.vt-modal-close');
  closeBtn.focus();
  closeBtn.addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

function formatVtOutput(raw, success) {
  if (success === undefined) return `<div class="vt-loading">${escapeHtml(raw)}</div>`;
  if (!success) return `<pre class="vt-output vt-error">${escapeHtml(raw)}</pre>`;
  const lines = String(raw).split('\n');
  let html = '';
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.includes('malicious:')) {
      const count = parseInt((trimmed.match(/malicious:\s*(\d+)/) || [])[1], 10) || 0;
      html += `<div class="vt-stat-line ${count > 0 ? 'vt-stat-bad' : 'vt-stat-good'}">${escapeHtml(line)}</div>`;
    } else if (trimmed.includes('suspicious:')) {
      const count = parseInt((trimmed.match(/suspicious:\s*(\d+)/) || [])[1], 10) || 0;
      html += `<div class="vt-stat-line ${count > 0 ? 'vt-stat-warn' : 'vt-stat-good'}">${escapeHtml(line)}</div>`;
    } else if (trimmed.includes('harmless:')) {
      html += `<div class="vt-stat-line vt-stat-good">${escapeHtml(line)}</div>`;
    } else if (trimmed.includes('undetected:')) {
      html += `<div class="vt-stat-line vt-stat-neutral">${escapeHtml(line)}</div>`;
    } else if (trimmed.startsWith('-')) {
      html += `<div class="vt-section">${escapeHtml(line)}</div>`;
    } else {
      html += `<div class="vt-line">${escapeHtml(line)}</div>`;
    }
  }
  return `<div class="vt-output">${html}</div>`;
}

// ---------- Blocked history modal (full history + bulk actions) ----------
async function showBlockedListModal() {
  const existing = document.getElementById('blockedListOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'blockedListOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="blocked-modal">
      <div class="vt-modal-header">
        <span class="vt-modal-title">Blocked IPs · History</span>
        <button class="vt-modal-close" data-close="1">×</button>
      </div>
      <div class="blocked-modal-body"><div class="vt-loading">Loading…</div></div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const close = () => { document.removeEventListener('keydown', onEsc); release(); overlay.remove(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
  document.addEventListener('keydown', onEsc);
  overlay.querySelector('.vt-modal-close')?.focus();
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay || e.target.dataset.close === '1') close();
  });
  await renderBlockedListBody(overlay, { selectMode: false });
}

async function renderBlockedListBody(overlay, { selectMode }) {
  const body = overlay.querySelector('.blocked-modal-body');
  body.innerHTML = '<div class="vt-loading">Loading…</div>';
  let data;
  try {
    const res = await apiFetch('/api/block-history');
    data = await res.json();
  } catch (err) {
    body.innerHTML = `<div class="vt-output vt-error">Failed to load: ${escapeHtml(err.message)}</div>`;
    return;
  }
  const rows = buildBlockedRows(data.history || []);
  const hasActive = rows.some(r => r.status === 'active');
  const effectiveSelect = selectMode && hasActive;
  const toolbar = `
    <div class="blocked-toolbar">
      <button data-action="manual-add">+ Block IP…</button>
      <button class="${effectiveSelect ? 'active' : ''}" ${hasActive ? '' : 'disabled'} data-action="toggle-select">${effectiveSelect ? 'Cancel' : 'Select'}</button>
      <button data-action="unblock-selected" ${effectiveSelect ? '' : 'hidden'} disabled>Unblock Selected <span class="blocked-sel-count">(0)</span></button>
    </div>
  `;
  if (rows.length === 0) {
    body.innerHTML = toolbar + '<div class="blocked-empty">No blocks recorded yet.</div>';
    wireBlockedToolbar(body, overlay, effectiveSelect);
    return;
  }
  body.innerHTML = toolbar + `
    <table class="blocked-table ${effectiveSelect ? 'select-mode' : ''}">
      <thead><tr>
        ${effectiveSelect ? '<th></th>' : ''}
        <th>IP</th><th>Country</th><th>Blocked At</th><th>Status</th><th></th>
      </tr></thead>
      <tbody>${rows.map(r => {
        const isActive = r.status === 'active';
        const ipEsc = escapeHtml(r.ip);
        return `<tr data-ip="${ipEsc}" data-active="${isActive ? '1' : '0'}">
          ${effectiveSelect ? `<td>${isActive ? `<input type="checkbox" class="blocked-row-check">` : ''}</td>` : ''}
          <td><code>${ipEsc}</code></td>
          <td>${r.country ? escapeHtml(r.country) : '<span class="geo-unknown">-</span>'}</td>
          <td>${escapeHtml(formatTime(r.blockedAt))}</td>
          <td>${isActive
            ? '<span class="blocked-tag">ACTIVE</span>'
            : r.status === 'superseded'
              ? `<span class="geo-unknown">Replaced ${escapeHtml(formatTime(r.unblockedAt))}</span>`
              : `<span class="geo-unknown">Unblocked ${escapeHtml(formatTime(r.unblockedAt))}</span>`}</td>
          <td>${isActive
            ? `<button class="blocked-row-unblock" data-unblock="${ipEsc}">Unblock</button>`
            : `<span class="blocked-row-actions">
                 <button class="blocked-row-reblock icon-btn" data-reblock="${ipEsc}" title="Re-block">⟲</button>
                 <button class="blocked-row-remove icon-btn" data-remove="${ipEsc}"
                   data-blocked-at="${r.blockedAt}"
                   ${r.status === 'unblocked' ? `data-unblocked-at="${r.unblockedAt}"` : ''}
                   title="Delete row">🗑</button>
               </span>`}
          </td>
        </tr>`;
      }).join('')}
      </tbody>
    </table>
  `;
  wireBlockedToolbar(body, overlay, effectiveSelect);
}

function wireBlockedToolbar(body, overlay, selectMode) {
  const toggleBtn = body.querySelector('[data-action="toggle-select"]');
  const bulkBtn = body.querySelector('[data-action="unblock-selected"]');
  const addBtn = body.querySelector('[data-action="manual-add"]');
  const countEl = body.querySelector('.blocked-sel-count');
  const updateBulkState = () => {
    const n = body.querySelectorAll('.blocked-row-check:checked').length;
    if (countEl) countEl.textContent = `(${n})`;
    if (bulkBtn) bulkBtn.disabled = n === 0;
  };
  if (toggleBtn) toggleBtn.addEventListener('click', () => renderBlockedListBody(overlay, { selectMode: !selectMode }));
  if (addBtn) addBtn.addEventListener('click', () => blockIPManualAction(overlay, selectMode));
  body.querySelectorAll('.blocked-row-check').forEach(cb => cb.addEventListener('change', updateBulkState));
  if (bulkBtn) bulkBtn.addEventListener('click', () => {
    const ips = Array.from(body.querySelectorAll('.blocked-row-check:checked')).map(cb => cb.closest('tr')?.dataset.ip).filter(Boolean);
    if (ips.length === 0) return;
    unblockBulkAction(ips, overlay);
  });
  body.querySelectorAll('.blocked-row-unblock').forEach(btn => {
    btn.addEventListener('click', () => {
      const ip = btn.dataset.unblock;
      askSudoPassword('Unblock', ip, async (password) => {
        if (!password) return;
        try {
          const r = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
          password = '';
          showToast(r.message, r.success ? 'success' : 'error');
          if (r.success) { blockedIPs.delete(ip); await fetchBlockedIPs(); await renderBlockedListBody(overlay, { selectMode }); }
        } catch (err) { showToast('Failed to unblock IP: ' + err.message, 'error'); }
      });
    });
  });
  body.querySelectorAll('.blocked-row-reblock').forEach(btn => {
    btn.addEventListener('click', () => {
      const ip = btn.dataset.reblock;
      askSudoPassword('Block', ip, async (password) => {
        if (!password) return;
        try {
          const r = await sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password);
          password = '';
          showToast(r.message, r.success ? 'success' : 'error');
          if (r.success) { blockedIPs.add(ip); await fetchBlockedIPs(); await renderBlockedListBody(overlay, { selectMode }); }
        } catch (err) { showToast('Failed to reblock IP: ' + err.message, 'error'); }
      });
    });
  });
  body.querySelectorAll('.blocked-row-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (btn.disabled) return;
      const ip = btn.dataset.remove;
      const blockedAt = btn.dataset.blockedAt;
      if (!ip || !blockedAt) return;
      btn.disabled = true;
      try {
        const q = new URLSearchParams({ blockedAt });
        if (btn.dataset.unblockedAt) q.set('unblockedAt', btn.dataset.unblockedAt);
        const res = await apiFetch(`/api/block-history/${encodeURIComponent(ip)}?${q}`, { method: 'DELETE' });
        const result = await res.json();
        if (res.ok && result.success) {
          showToast(result.removed === 0 ? `Nothing to remove for ${ip}` : `Removed row for ${ip}`, 'success');
          await renderBlockedListBody(overlay, { selectMode });
        } else {
          showToast(result.message || 'Failed to remove row', 'error');
        }
      } catch (err) {
        showToast('Failed to remove row: ' + err.message, 'error');
      } finally {
        if (btn.isConnected) btn.disabled = false;
      }
    });
  });
}

function looksLikeIP(s) {
  if (typeof s !== 'string') return false;
  const v = s.trim();
  if (v.length === 0 || v.length > 45) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return v.split('.').every(o => Number(o) <= 255);
  if (v.includes(':') && /^[0-9a-fA-F:.]+$/.test(v)) return true;
  return false;
}

function blockIPManualAction(overlay, selectMode) {
  const existing = document.getElementById('manualBlockOverlay');
  if (existing) existing.remove();
  const dialog = document.createElement('div');
  dialog.id = 'manualBlockOverlay';
  dialog.className = 'confirm-overlay';
  dialog.setAttribute('role', 'dialog');
  dialog.setAttribute('aria-modal', 'true');
  dialog.innerHTML = `
    <div class="confirm-dialog sudo-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">
        <div class="sudo-title">Block IP manually</div>
        <div class="sudo-body">Add an IPv4 or IPv6 address to the <code>pfctl</code> block table.</div>
      </div>
      <input type="text" class="sudo-input manual-ip-input" placeholder="e.g. 1.2.3.4" autocomplete="off" />
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-kill manual-submit">Continue</button>
      </div>
    </div>
  `;
  document.body.appendChild(dialog);
  const release = trapFocus(dialog);
  const input = dialog.querySelector('.manual-ip-input');
  input.focus();
  const close = () => { document.removeEventListener('keydown', onEsc); release(); dialog.remove(); };
  // Escape closes from anywhere in the dialog, not only while the input is focused.
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
  document.addEventListener('keydown', onEsc);
  const submit = () => {
    const ip = input.value.trim();
    if (!looksLikeIP(ip)) { showToast('Invalid IP format', 'error'); input.focus(); return; }
    close();
    askSudoPassword('Block', ip, async (password) => {
      if (!password) return;
      try {
        const r = await sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password);
        password = '';
        showToast(r.message, r.success ? 'success' : 'error');
        if (r.success) {
          blockedIPs.add(ip);
          await fetchBlockedIPs();
          if (overlay) await renderBlockedListBody(overlay, { selectMode });
        }
      } catch (err) { showToast('Failed to block IP: ' + err.message, 'error'); }
    });
  };
  dialog.querySelector('.confirm-cancel').addEventListener('click', close);
  dialog.querySelector('.manual-submit').addEventListener('click', submit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
  });
  dialog.addEventListener('click', (e) => { if (e.target === dialog) close(); });
}

function unblockBulkAction(ips, overlay) {
  const representative = ips.length === 1 ? ips[0] : `${ips[0]} + ${ips.length - 1} more`;
  askSudoPassword(`Unblock ${ips.length} IP${ips.length === 1 ? '' : 's'}`, representative, async (password) => {
    if (!password) return;
    let ok = 0, fail = 0, aborted = false;
    try {
      for (const ip of ips) {
        try {
          const r = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
          if (r.success) { ok += 1; blockedIPs.delete(ip); }
          else {
            fail += 1;
            if (typeof r.message === 'string' && /sudo authentication/i.test(r.message)) { aborted = true; break; }
          }
        } catch { fail += 1; }
      }
    } finally { password = ''; }
    const remaining = ips.length - ok - fail;
    const msg = aborted
      ? `Aborted — sudo auth failed. Unblocked ${ok}, skipped ${remaining}.`
      : fail === 0 ? `Unblocked ${ok} IP${ok === 1 ? '' : 's'}` : `Unblocked ${ok}, failed ${fail}`;
    showToast(msg, fail === 0 && !aborted ? 'success' : 'error');
    await fetchBlockedIPs();
    await renderBlockedListBody(overlay, { selectMode: false });
  });
}

function buildBlockedRows(history) {
  const byIp = new Map();
  for (const ev of history) {
    if (!byIp.has(ev.ip)) byIp.set(ev.ip, []);
    byIp.get(ev.ip).push(ev);
  }
  const rows = [];
  for (const [ip, events] of byIp) {
    events.sort((a, b) => a.at - b.at);
    let pending = null;
    for (const ev of events) {
      if (ev.action === 'block') {
        if (pending) rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'superseded', unblockedAt: ev.at });
        pending = ev;
      } else if (ev.action === 'unblock' && pending) {
        rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'unblocked', unblockedAt: ev.at });
        pending = null;
      }
    }
    if (pending) rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'active' });
  }
  const rank = (s) => (s === 'active' ? 0 : 1);
  rows.sort((a, b) => rank(a.status) - rank(b.status) || b.blockedAt - a.blockedAt);
  return rows;
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// ---------- SSE: live traffic ----------
function connectTrafficStream() {
  let es;
  try { es = new EventSource('/api/traffic-stream'); }
  catch (err) { console.warn('[traffic] EventSource unsupported', err); return; }

  es.addEventListener('delta', (ev) => {
    let arr;
    try { arr = JSON.parse(ev.data); } catch { return; }
    if (!Array.isArray(arr)) return;

    streamHealthy = true;
    lastDeltaAt = Date.now();

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
    streamHealthy = false;
  });
  es.addEventListener('open', () => { streamHealthy = true; });

  // Decay the throughput readout to 0 when no deltas arrive (the server only
  // emits a delta when traffic > 0). Paused while the tab is hidden.
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    if (lastDeltaAt && Date.now() - lastDeltaAt >= 1500) {
      pushThroughput(0, 0);
      lastDeltaAt = Date.now(); // keep ticking 0s while idle, but only once/window
    }
  }, 1000);
}

// ---------- Throughput history / graph ----------
let rxHistory = Array(40).fill(0), txHistory = Array(40).fill(0);
function pushThroughput(rxBps, txBps) {
  rxHistory.push(rxBps); rxHistory.shift();
  txHistory.push(txBps); txHistory.shift();
  const toMB = (b) => (b / (1024 * 1024)).toFixed(2);
  tRx.textContent = toMB(rxBps);
  tTx.textContent = toMB(txBps);
  drawGraph(gRx, rxHistory, getComputedStyle(document.body).getPropertyValue('--ice').trim());
  drawGraph(gTx, txHistory, getComputedStyle(document.body).getPropertyValue('--signal').trim());
}
function drawGraph(svg, arr, color) {
  if (!svg) return;
  const max = Math.max(...arr, 1);
  const pts = arr.map((v, i) => `${(i / (arr.length - 1)) * 100},${48 - (v / max) * 44}`);
  svg.innerHTML = `
    <polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="1.2" />
    <polygon points="0,48 ${pts.join(' ')} 100,48" fill="${color}" fill-opacity="0.14" />
  `;
}

// ---------- Radar canvas ----------
const radarCanvas = document.getElementById('radar');
const radarCtx = radarCanvas.getContext('2d');
let RW = 0, RH = 0, CX = 0, CY = 0, RR = 0;
const DPR = Math.max(1, window.devicePixelRatio || 1);
let homeLat = null, homeLon = null;
let radarTargets = []; // { lat, lng, pt, hot, label, bytes }
let sweepAngle = -Math.PI / 2;
let lastT = 0;
let radarOn = true;
// Pause the rAF loop when the radar isn't visible — tab hidden, scrolled
// out of view, or container display:none. requestAnimationFrame is already
// throttled to 1Hz when the tab is hidden, but the per-frame redraw
// (rings, 72 ticks, home, sweep, arcs, targets) is still wasted work.
let radarVisible = true;
let radarTabVisible = !document.hidden;
let radarRafScheduled = false;
function radarShouldRun() { return radarOn && radarVisible && radarTabVisible; }
function scheduleRadarFrame() {
  if (radarRafScheduled || !radarShouldRun()) return;
  radarRafScheduled = true;
  requestAnimationFrame(radarFrame);
}
// Reduced-motion freezes the sweep and stops the rAF loop self-scheduling.
// Re-check via this shared query (not a fresh matchMedia() per frame) and
// restart the loop if the user toggles the OS setting OFF while the page is open.
const motionQuery = window.matchMedia ? matchMedia('(prefers-reduced-motion: reduce)') : null;
motionQuery?.addEventListener?.('change', () => { lastT = 0; scheduleRadarFrame(); });
document.addEventListener('visibilitychange', () => {
  radarTabVisible = !document.hidden;
  lastT = 0; // avoid a huge dt jump on resume
  scheduleRadarFrame();
});

function sizeRadar() {
  const parent = radarCanvas.parentElement;
  const rect = parent.getBoundingClientRect();
  // Round to integer CSS pixels: the canvas has CSS width:100% which
  // rounds to nearest device pixel on its own. If our internal RW/RH
  // are sub-pixel, CX/CY drift off-center and targets appear to shift
  // as the browser rescales each redraw.
  const w = Math.floor(rect.width);
  const h = Math.floor(rect.height);
  if (w === RW && h === RH) return;
  RW = w; RH = h;
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  radarCanvas.width = Math.floor(RW * dpr);
  radarCanvas.height = Math.floor(RH * dpr);
  radarCanvas.style.width = RW + 'px';
  radarCanvas.style.height = RH + 'px';
  radarCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  CX = Math.round(RW / 2);
  CY = Math.round(RH / 2);
  RR = Math.floor(Math.min(RW, RH) / 2) - 24;
  layoutBearings();
  reprojectTargets();
  reprojectCountryBorders();
}
window.addEventListener('resize', sizeRadar);
// The radar-wrap size changes whenever the queue collapses, a modal
// opens, the stage rows rebalance (stats strip wraps), or the window
// resizes. Window resize alone misses all of those, which is what made
// the canvas resolution go stale and the pinpoints "drift" relative to
// the drawn rings. A ResizeObserver on the parent catches every case.
if (typeof ResizeObserver !== 'undefined') {
  new ResizeObserver(() => sizeRadar()).observe(radarCanvas.parentElement);
}

function layoutBearings() {
  const wrap = document.getElementById('bearings');
  if (!wrap) return;
  wrap.innerHTML = '';
  const cardinals = [
    { l: 'N 000', a: -Math.PI / 2 },
    { l: 'NE 045', a: -Math.PI / 4 },
    { l: 'E 090', a: 0 },
    { l: 'SE 135', a: Math.PI / 4 },
    { l: 'S 180', a: Math.PI / 2 },
    { l: 'SW 225', a: 3 * Math.PI / 4 },
    { l: 'W 270', a: Math.PI },
    { l: 'NW 315', a: -3 * Math.PI / 4 },
  ];
  for (const c of cardinals) {
    const el = document.createElement('span');
    el.textContent = c.l;
    const r = RR + 20;
    el.style.left = (CX + Math.cos(c.a) * r) + 'px';
    el.style.top = (CY + Math.sin(c.a) * r) + 'px';
    wrap.appendChild(el);
  }
}

function project(lat, lng) {
  if (homeLat === null) return { x: CX, y: CY, c: 0 };
  const φ1 = homeLat * Math.PI / 180;
  const λ1 = homeLon * Math.PI / 180;
  const φ2 = lat * Math.PI / 180;
  const λ2 = lng * Math.PI / 180;
  const c = Math.acos(Math.max(-1, Math.min(1, Math.sin(φ1) * Math.sin(φ2) + Math.cos(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1))));
  const y = Math.sin(λ2 - λ1) * Math.cos(φ2);
  const x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1);
  const θ = Math.atan2(y, x);
  const rr = (c / Math.PI) * RR * 1.15;
  return { x: CX + rr * Math.sin(θ), y: CY - rr * Math.cos(θ), c };
}

// ---- Country borders ----
// Lazy-loaded and cached. Each country is stored as an array of rings,
// each ring is an array of [lon, lat] pairs. We project & stroke these
// every radar frame. The azimuthal-equidistant projection degenerates
// near the antipode, so segments whose endpoints lie more than ~170°
// apart from the home point are skipped to avoid ugly long slashes.
let countryRings = null; // Array<Array<[lng, lat]>> | null (raw lon/lat)
let projectedCountryRings = null; // cached Array<Array<{x,y,c}>>; rebuilt only on home/size change
(async () => {
  try {
    // Pinned to an exact version (the topojson-client <script> is SRI-pinned to
    // @3.1.0). A fetch() can't carry SRI, so this is the practical hardening:
    // an immutable, reproducible URL. CSP connect-src already limits the host.
    const res = await fetch('https://unpkg.com/world-atlas@2.0.2/countries-110m.json');
    if (!res.ok) return;
    const topo = await res.json();
    const topojson = window.topojson;
    if (!topojson || !topo?.objects?.countries) return;
    const geo = topojson.feature(topo, topo.objects.countries);
    const rings = [];
    for (const feat of geo.features) {
      const geom = feat.geometry;
      if (!geom) continue;
      if (geom.type === 'Polygon') {
        for (const ring of geom.coordinates) rings.push(ring);
      } else if (geom.type === 'MultiPolygon') {
        for (const poly of geom.coordinates) {
          for (const ring of poly) rings.push(ring);
        }
      }
    }
    countryRings = rings;
    reprojectCountryBorders();
    scheduleRadarFrame();
  } catch {
    // CDN unavailable — radar just renders without borders.
  }
})();

// Rebuild the projected-border cache. The azimuthal projection depends only on
// the home point and radar size, so we re-project on home/size change — not on
// every frame; drawCountryBorders then just strokes the cached points.
function reprojectCountryBorders() {
  if (!countryRings || homeLat === null || RR <= 0) { projectedCountryRings = null; return; }
  projectedCountryRings = countryRings.map((ring) => ring.map(([lon, lat]) => project(lat, lon)));
}

function drawCountryBorders(ctx) {
  if (!projectedCountryRings) return;
  ctx.save();
  // Clip to radar disk so overshoots don't bleed outside the ring.
  ctx.beginPath();
  ctx.arc(CX, CY, RR * 1.06, 0, Math.PI * 2);
  ctx.clip();
  ctx.strokeStyle = 'oklch(0.40 0.01 260 / 0.55)';
  ctx.lineWidth = 0.6;
  const CUTOFF = Math.PI * 0.92; // skip near-antipode segments
  for (const ring of projectedCountryRings) {
    ctx.beginPath();
    let prev = null;
    for (const p of ring) {
      if (p.c > CUTOFF) { prev = null; continue; }
      if (prev === null) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
      prev = p;
    }
    ctx.stroke();
  }
  ctx.restore();
}

function reprojectTargets() {
  for (const t of radarTargets) t.pt = project(t.lat, t.lng);
}

function radarSetHome(lat, lon) {
  if (typeof lat !== 'number' || typeof lon !== 'number') return;
  homeLat = lat; homeLon = lon;
  reprojectTargets();
  reprojectCountryBorders();
}

function radarUpdateTargets(sortedProcs) {
  const seen = new Map(); // "lat,lng" -> target
  for (const p of sortedProcs) {
    for (const c of p.connections) {
      const g = c.geo;
      if (!g || g.country === 'Local' || (!g.lat && !g.lon)) continue;
      const key = `${g.lat.toFixed(2)},${g.lon.toFixed(2)}`;
      if (!seen.has(key)) {
        seen.set(key, {
          lat: g.lat, lng: g.lon,
          pt: project(g.lat, g.lng),
          hot: false,
          bytes: 0,
          label: `${g.countryCode || ''} · ${p.processName}`,
          conns: 0,
        });
      }
      const t = seen.get(key);
      const live = liveTraffic.get(c.trafficKey);
      t.bytes += (live ? live.bytesIn : (c.bytesIn || 0)) + (live ? live.bytesOut : (c.bytesOut || 0));
      t.conns += 1;
    }
  }
  // mark the top 3 by byte count as hot
  const arr = [...seen.values()];
  arr.sort((a, b) => b.bytes - a.bytes);
  arr.forEach((t, i) => { t.hot = i < 3 && t.bytes > 0; });
  radarTargets = arr;
}

function radarFrame(ts) {
  radarRafScheduled = false;
  if (!radarShouldRun()) return; // stop the loop; scheduleRadarFrame() resumes it
  // Honor reduced-motion: draw one static frame, don't run the sweep loop.
  const reduceMotion = !!motionQuery?.matches;
  if (!reduceMotion) {
    requestAnimationFrame(radarFrame);
    radarRafScheduled = true;
  }
  if (!lastT) lastT = ts;
  const dt = (ts - lastT) / 1000; lastT = ts;
  // Keep lastT current even under reduced-motion (avoids a dt jump if motion
  // is re-enabled), but freeze the sweep so refreshes don't visibly rotate it.
  if (!reduceMotion) {
    sweepAngle += dt * (Math.PI * 2 / 7);
    if (sweepAngle > Math.PI) sweepAngle -= Math.PI * 2;
  }

  const ctx = radarCtx;
  ctx.clearRect(0, 0, RW, RH);
  if (RR <= 0) return;

  // vignette
  const g = ctx.createRadialGradient(CX, CY, RR * 0.1, CX, CY, RR * 1.1);
  g.addColorStop(0, 'rgba(255,255,255,0.02)');
  g.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = g; ctx.fillRect(0, 0, RW, RH);

  // country borders (behind rings)
  drawCountryBorders(ctx);

  // rings
  ctx.strokeStyle = 'oklch(0.32 0.006 260)'; ctx.lineWidth = 1;
  for (const f of [0.25, 0.5, 0.75, 1.0]) {
    ctx.beginPath(); ctx.arc(CX, CY, RR * f, 0, Math.PI * 2); ctx.stroke();
  }
  ctx.strokeStyle = 'oklch(0.50 0.006 260)';
  ctx.beginPath(); ctx.arc(CX, CY, RR * 1.08, 0, Math.PI * 2); ctx.stroke();

  // crosshair
  ctx.strokeStyle = 'oklch(0.25 0.006 260)'; ctx.setLineDash([2, 4]);
  ctx.beginPath();
  ctx.moveTo(CX - RR * 1.05, CY); ctx.lineTo(CX + RR * 1.05, CY);
  ctx.moveTo(CX, CY - RR * 1.05); ctx.lineTo(CX, CY + RR * 1.05);
  const d = RR * 1.05 / Math.SQRT2;
  ctx.moveTo(CX - d, CY - d); ctx.lineTo(CX + d, CY + d);
  ctx.moveTo(CX - d, CY + d); ctx.lineTo(CX + d, CY - d);
  ctx.stroke(); ctx.setLineDash([]);

  // ticks
  ctx.strokeStyle = 'oklch(0.35 0.006 260)';
  for (let a = 0; a < 360; a += 5) {
    const rad = a * Math.PI / 180;
    const big = a % 15 === 0;
    const r1 = RR * 1.08, r2 = RR * (big ? 1.12 : 1.10);
    ctx.beginPath();
    ctx.moveTo(CX + Math.cos(rad) * r1, CY + Math.sin(rad) * r1);
    ctx.lineTo(CX + Math.cos(rad) * r2, CY + Math.sin(rad) * r2);
    ctx.stroke();
  }

  // home
  ctx.fillStyle = '#fff';
  ctx.beginPath(); ctx.arc(CX, CY, 3.5, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = 'rgba(255,255,255,0.4)';
  ctx.beginPath(); ctx.arc(CX, CY, 8 + Math.sin(ts / 400) * 2, 0, Math.PI * 2); ctx.stroke();

  // sweep cone + line
  const signal = 'oklch(0.74 0.25 340)';
  const grad = ctx.createRadialGradient(CX, CY, 0, CX, CY, RR * 1.08);
  grad.addColorStop(0, 'rgba(0,0,0,0)');
  grad.addColorStop(1, 'oklch(0.74 0.25 340 / 0.35)');
  ctx.save(); ctx.translate(CX, CY); ctx.rotate(sweepAngle);
  ctx.beginPath(); ctx.moveTo(0, 0);
  const spread = Math.PI / 5;
  ctx.arc(0, 0, RR * 1.08, -spread, 0); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();
  ctx.restore();

  ctx.save(); ctx.translate(CX, CY); ctx.rotate(sweepAngle);
  ctx.strokeStyle = signal; ctx.lineWidth = 1.4; ctx.shadowColor = signal; ctx.shadowBlur = 10;
  ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(RR * 1.08, 0); ctx.stroke();
  ctx.shadowBlur = 0; ctx.restore();

  // arcs
  ctx.strokeStyle = 'oklch(0.84 0.11 230 / 0.18)'; ctx.lineWidth = 0.8;
  for (const t of radarTargets) {
    ctx.beginPath();
    ctx.moveTo(CX, CY);
    const mx = (CX + t.pt.x) / 2, my = (CY + t.pt.y) / 2;
    const ndx = -(t.pt.y - CY), ndy = (t.pt.x - CX);
    const ln = Math.hypot(ndx, ndy) || 1;
    const k = 0.18;
    const cx2 = mx + ndx / ln * Math.hypot(t.pt.x - CX, t.pt.y - CY) * k;
    const cy2 = my + ndy / ln * Math.hypot(t.pt.x - CX, t.pt.y - CY) * k;
    ctx.quadraticCurveTo(cx2, cy2, t.pt.x, t.pt.y);
    ctx.stroke();
  }

  // targets
  for (const t of radarTargets) {
    const { x, y } = t.pt;
    const ang = Math.atan2(y - CY, x - CX);
    const rel = (sweepAngle - ang + Math.PI * 2) % (Math.PI * 2);
    const tail = Math.PI / 2.5;
    const illum = rel < tail ? 1 - rel / tail : 0;
    const baseAlpha = 0.55 + illum * 0.45;
    const color = t.hot ? 'oklch(0.74 0.25 340)' : 'oklch(0.84 0.11 230)';
    ctx.fillStyle = color; ctx.globalAlpha = baseAlpha;
    ctx.beginPath(); ctx.arc(x, y, t.hot ? 2.8 : 2.2, 0, Math.PI * 2); ctx.fill();
    if (illum > 0.2) {
      ctx.globalAlpha = illum * 0.6;
      ctx.strokeStyle = color; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(x, y, 6 + illum * 6, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }
}
sizeRadar();
scheduleRadarFrame();

// Watch whether the radar is actually on-screen (tweaks can hide it via
// `display:none`, the queue can push it below the fold, etc.). Combined
// with the visibilitychange listener, this means the canvas redraws only
// when pixels on screen actually depend on it.
if (typeof IntersectionObserver !== 'undefined') {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      radarVisible = e.isIntersecting;
      if (radarVisible) {
        lastT = 0;
        scheduleRadarFrame();
      }
    }
  }, { threshold: 0 });
  io.observe(radarCanvas);
}

// ---------- System health (live from /api/system-health) ----------
function fmtBytes(n) {
  if (n == null) return '—';
  const gb = n / (1024 ** 3);
  return gb >= 1 ? gb.toFixed(1) + ' GB' : (n / (1024 ** 2)).toFixed(0) + ' MB';
}
async function refreshSystemHealth() {
  try {
    const res = await apiFetch('/api/system-health');
    if (!res.ok) throw new Error(res.statusText);
    const h = await res.json();
    if (h.cpu == null) {
      hCPU.textContent = '—';
      hCPUbar.style.width = '0%';
    } else {
      hCPU.textContent = h.cpu.toFixed(0) + '%';
      hCPUbar.style.width = h.cpu.toFixed(0) + '%';
    }
    if (h.memUsedBytes == null) {
      hMem.textContent = `— / ${fmtBytes(h.memTotalBytes)}`;
      hMembar.style.width = '0%';
    } else {
      const pct = (h.memUsedBytes / h.memTotalBytes) * 100;
      hMem.textContent = `${fmtBytes(h.memUsedBytes)} / ${fmtBytes(h.memTotalBytes)}`;
      hMembar.style.width = pct.toFixed(0) + '%';
    }
    const [l1, l5, l15] = h.load;
    hLoad.textContent = `${l1.toFixed(2)} / ${l5.toFixed(2)} / ${l15.toFixed(2)}`;
  } catch {
    // leave previous values in place on transient failure
  }
}
refreshSystemHealth();
setInterval(() => {
  // Skip polling while the tab is hidden — browsers already throttle
  // background timers, but skipping outright avoids piling up two
  // coincident pollers (this one + the connections poll) on focus.
  if (document.visibilityState !== 'visible') return;
  refreshSystemHealth();
}, 2200);

// ---------- Tweaks ----------
const TWEAKS = JSON.parse(localStorage.getItem('nw-tweaks') || 'null') || { density: 'compact', radar: true };
function applyTweaks() {
  document.body.classList.toggle('density-compact', TWEAKS.density === 'compact');
  document.body.classList.toggle('density-comfortable', TWEAKS.density === 'comfortable');
  document.body.classList.toggle('radar-off', !TWEAKS.radar);
  radarOn = TWEAKS.radar !== false;
  if (radarOn) { lastT = 0; scheduleRadarFrame(); }
  for (const seg of document.querySelectorAll('.tweaks .seg')) {
    const k = seg.dataset.key;
    for (const b of seg.querySelectorAll('button')) b.classList.toggle('on', b.dataset.v === TWEAKS[k]);
  }
  document.getElementById('twRadar').classList.toggle('on', !!TWEAKS.radar);
  localStorage.setItem('nw-tweaks', JSON.stringify(TWEAKS));
}
document.querySelectorAll('.tweaks .seg').forEach(seg => {
  seg.addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    TWEAKS[seg.dataset.key] = b.dataset.v;
    applyTweaks();
  });
});
document.getElementById('twRadar').addEventListener('click', () => {
  TWEAKS.radar = !TWEAKS.radar;
  applyTweaks();
});
applyTweaks();

// ---------- Refresh orchestration ----------
async function refreshAll({ fresh } = { fresh: false }) {
  await Promise.all([fetchConnections(), fetchHostInfo({ fresh }), fetchBlockedIPs()]);
}
function scheduleRefresh() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  if (refreshIntervalMs > 0) refreshTimer = setInterval(() => refreshAll({ fresh: false }), refreshIntervalMs);
}
refreshSelect.addEventListener('change', () => {
  refreshIntervalMs = parseInt(refreshSelect.value, 10) || 2000;
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

// ---------- Init ----------
statusText.classList.add('wait');
statusText.textContent = 'connecting…';
connectTrafficStream();
refreshAll({ fresh: true });
scheduleRefresh();
