/* ============================================================
   NetWatcher — wiring real API to the Radar Room redesign
   ============================================================ */

// ---------- DOM ----------
const queueEl = document.getElementById('queue');
const qEl = document.getElementById('searchInput');
const sortSelect = document.getElementById('sortSelect');
const chipsEl = document.getElementById('chips');
const procCountEl = document.getElementById('procCount');
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
const hTemp = document.getElementById('hTemp');
const hTempbar = document.getElementById('hTempbar');
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
let lastData = null;
let hostInfo = null;
let blockedIPs = new Set();
let blockedMeta = new Map(); // ip -> { country, blockedAt }
let refreshTimer = null;
let refreshIntervalMs = 300000;
const liveTraffic = new Map();        // trafficKey -> { bytesIn, bytesOut }
const prevConnBytes = new Map();      // connId -> bytes
// Filter toggles — mirror the chip states on load.
const filter = { sys: true, v6: true, priv: true, q: '' };
let blockedQ = '';

const CSRF_HEADER = { 'x-requested-by': 'netwatcher' };

// ---------- Helpers ----------
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
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
function clientTrafficKey(protocol, localIP, localPort, remoteIP, remotePort) {
  const normalize = (ip) => {
    let out = String(ip).replace(/%.+$/, '');
    out = out.replace(/^fe80:[0-9a-f]{1,4}::/i, 'fe80::');
    return out.toLowerCase();
  };
  const p = String(protocol).toLowerCase();
  const proto = p.startsWith('tcp') ? 'tcp' : p.startsWith('udp') ? 'udp' : p;
  return `${proto}|${normalize(localIP)}|${localPort}|${normalize(remoteIP)}|${remotePort}`;
}

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
    const tk = clientTrafficKey(c.protocol, c.localAddress, c.localPort, c.remoteAddress, c.remotePort);
    const live = liveTraffic.get(tk);
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
function updateExpandToggle() {
  const btn = document.getElementById('expandToggleChip');
  if (!btn || !lastData) return;
  const visible = applyFilters(lastData);
  const allOpen = visible.length > 0 && visible.every((p) => expandedPids.has(p.pid));
  btn.classList.toggle('all-expanded', allOpen);
  const lbl = btn.querySelector('.lbl');
  if (lbl) lbl.textContent = allOpen ? 'collapse all' : 'expand all';
  btn.title = allOpen ? 'Collapse all' : 'Expand all';
}

function renderQueue() {
  if (!lastData) {
    queueEl.innerHTML = '<div class="queue-empty">Loading connections…</div>';
    return;
  }
  const filtered = applyFilters(lastData);
  const sorted = sortProcesses(filtered);

  procCountEl.textContent = `${sorted.length} visible`;
  updateExpandToggle();

  if (sorted.length === 0) {
    queueEl.innerHTML = '<div class="queue-empty">No connections match current filters</div>';
  } else {
    queueEl.innerHTML = sorted.map((p, i) => renderProcRow(p, i)).join('');
  }

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

  renderTopTalkers(sorted);
  radarUpdateTargets(sorted);
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
    <div class="row ${proc.isSystemProcess ? 'sys' : ''} ${expanded ? 'active' : ''}" data-action="toggle" data-pid="${proc.pid}">
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

    const dom = conn.domain && conn.domain !== '-'
      ? `<span class="dom">${escapeHtml(conn.domain)}</span>`
      : '';

    const tKey = clientTrafficKey(conn.protocol, conn.localAddress, conn.localPort, conn.remoteAddress, conn.remotePort);
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
      const tk = clientTrafficKey(c.protocol, c.localAddress, c.localPort, c.remoteAddress, c.remotePort);
      const live = liveTraffic.get(tk);
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
  e.stopPropagation();
  if (action === 'kill') {
    killProcessAction(Number(el.dataset.pid), el.dataset.name, el.dataset.system === '1');
  } else if (action === 'vt') {
    vtCheckAction(el.dataset.ip);
  } else if (action === 'block') {
    blockIPAction(el.dataset.ip);
  } else if (action === 'unblock') {
    unblockIPAction(el.dataset.ip);
  }
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
    const res = await fetch('/api/host-info' + (fresh ? '?fresh=1' : ''));
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
    const res = await fetch('/api/connections');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    lastData = data;
    statusText.textContent = 'streaming · live';
    statusText.classList.remove('err', 'wait');
    renderQueue();
  } catch (err) {
    statusText.textContent = 'error';
    statusText.classList.add('err');
  }
}

// ---------- API: blocked ----------
async function fetchBlockedIPs() {
  try {
    const res = await fetch('/api/blocked');
    if (!res.ok) return;
    const ips = await res.json();
    blockedIPs = new Set(ips);
  } catch { /* silent */ }
  // Pull richer metadata (country, blockedAt) from the history endpoint.
  try {
    const res = await fetch('/api/block-history');
    if (!res.ok) throw 0;
    const data = await res.json();
    blockedMeta = new Map();
    for (const rec of (data.active || [])) {
      blockedMeta.set(rec.ip, { country: rec.country, blockedAt: rec.blockedAt });
    }
  } catch { /* silent */ }
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
    const hay = `${ip} ${meta?.country || ''}`.toLowerCase();
    return !q || hay.includes(q);
  });
  if (filtered.length === 0) {
    blockedListEl.innerHTML = `<div class="blocked-empty">${q ? `No blocked addresses match “${escapeHtml(q)}”` : 'No IPs currently blocked'}</div>`;
    return;
  }
  blockedListEl.innerHTML = filtered.map(ip => {
    const meta = blockedMeta.get(ip) || {};
    const cc = meta.country || '';
    const f = flag(cc);
    const when = meta.blockedAt ? relTime(meta.blockedAt) : '—';
    return `
      <div class="blocked-row" data-ip="${escapeHtml(ip)}">
        <span class="ip">${escapeHtml(ip)}</span>
        <span class="cc">${f} ${escapeHtml(cc)}</span>
        <span class="host"></span>
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
async function sendFirewallRequest(path, ip, password) {
  let body = JSON.stringify({ password });
  password = '';
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: { ...CSRF_HEADER, 'Content-Type': 'application/json' },
      body,
    });
    body = '';
    return await res.json();
  } finally {
    body = '';
  }
}

function blockIPAction(ip) {
  askSudoPassword('Block', ip, async (password) => {
    if (!password) return;
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
    }
  });
}
function unblockIPAction(ip) {
  askSudoPassword('Unblock', ip, async (password) => {
    if (!password) return;
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
    }
  });
}

function killProcessAction(pid, name, isSystem) {
  if (isSystem) {
    showConfirmDialog(
      `"${name}" is a system process required for system stability. Are you sure you want to kill it?`,
      () => doKill(pid),
    );
    return;
  }
  doKill(pid);
}
async function doKill(pid) {
  try {
    const res = await fetch(`/api/kill/${pid}`, { method: 'POST', headers: CSRF_HEADER });
    const result = await res.json();
    showToast(result.message, result.success ? 'success' : 'error');
    setTimeout(fetchConnections, 500);
  } catch (err) {
    showToast('Failed to kill process: ' + err.message, 'error');
  }
}

async function vtCheckAction(ip) {
  showVtModal(ip, 'Loading VirusTotal data…');
  try {
    const res = await fetch(`/api/vt/${encodeURIComponent(ip)}`);
    const data = await res.json();
    showVtModal(ip, data.output, data.success);
  } catch (err) {
    showVtModal(ip, 'Failed to reach VT endpoint: ' + err.message, false);
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

function showConfirmDialog(message, onConfirm) {
  const existing = document.getElementById('confirmOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'confirmOverlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="confirm-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">${escapeHtml(message)}</div>
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-kill">Kill Anyway</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('.confirm-cancel').addEventListener('click', () => overlay.remove());
  overlay.querySelector('.confirm-kill').addEventListener('click', () => { overlay.remove(); onConfirm(); });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

function askSudoPassword(action, ip, onSubmit) {
  const existing = document.getElementById('sudoOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'sudoOverlay';
  overlay.className = 'confirm-overlay';
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
        <button class="confirm-btn confirm-kill sudo-submit">Proceed</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const input = overlay.querySelector('.sudo-input');
  input.focus();
  const cleanup = (submitted) => {
    let pwd = submitted ? input.value : '';
    input.value = '';
    overlay.remove();
    return pwd;
  };
  const cancel = () => { cleanup(false); };
  const submit = () => onSubmit(cleanup(true));
  overlay.querySelector('.confirm-cancel').addEventListener('click', cancel);
  overlay.querySelector('.sudo-submit').addEventListener('click', submit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
    else if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) cancel(); });
}

function showVtModal(ip, content, success) {
  const existing = document.getElementById('vtOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'vtOverlay';
  overlay.className = 'confirm-overlay';
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
  overlay.querySelector('.vt-modal-close').addEventListener('click', () => overlay.remove());
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
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
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay || e.target.dataset.close === '1') overlay.remove();
  });
  await renderBlockedListBody(overlay, { selectMode: false });
}

async function renderBlockedListBody(overlay, { selectMode }) {
  const body = overlay.querySelector('.blocked-modal-body');
  body.innerHTML = '<div class="vt-loading">Loading…</div>';
  let data;
  try {
    const res = await fetch('/api/block-history');
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
        const res = await fetch(`/api/block-history/${encodeURIComponent(ip)}?${q}`, { method: 'DELETE', headers: CSRF_HEADER });
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
  const input = dialog.querySelector('.manual-ip-input');
  input.focus();
  const close = () => dialog.remove();
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
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
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

    let rxBytesPerSec = 0, txBytesPerSec = 0;
    for (const e of arr) {
      if (!e || typeof e.key !== 'string') continue;
      const prevBytes = liveTraffic.get(e.key);
      if (prevBytes) {
        const drx = Math.max(0, e.bytesIn - prevBytes.bytesIn);
        const dtx = Math.max(0, e.bytesOut - prevBytes.bytesOut);
        rxBytesPerSec += drx;
        txBytesPerSec += dtx;
      }
      liveTraffic.set(e.key, { bytesIn: e.bytesIn | 0, bytesOut: e.bytesOut | 0 });
      // Patch the row in place if visible.
      const sel = `.c[data-traffic-key="${CSS.escape(e.key)}"]`;
      const row = document.querySelector(sel);
      if (!row) continue;
      const rxEl = row.querySelector('[data-role="rx"]');
      const txEl = row.querySelector('[data-role="tx"]');
      if (rxEl) rxEl.textContent = `↓${formatBytes(e.bytesIn)}`;
      if (txEl) txEl.textContent = `↑${formatBytes(e.bytesOut)}`;
    }
    // Push the tick into throughput history. The stream delivers roughly 1/s.
    pushThroughput(rxBytesPerSec, txBytesPerSec);
  });

  es.addEventListener('error', () => {
    // EventSource reconnects on its own.
  });
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
  RR = Math.floor(Math.min(RW, RH) / 2) - 40;
  layoutBearings();
  reprojectTargets();
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
  if (homeLat === null) return { x: CX, y: CY };
  const φ1 = homeLat * Math.PI / 180;
  const λ1 = homeLon * Math.PI / 180;
  const φ2 = lat * Math.PI / 180;
  const λ2 = lng * Math.PI / 180;
  const c = Math.acos(Math.max(-1, Math.min(1, Math.sin(φ1) * Math.sin(φ2) + Math.cos(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1))));
  const y = Math.sin(λ2 - λ1) * Math.cos(φ2);
  const x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1);
  const θ = Math.atan2(y, x);
  const rr = (c / Math.PI) * RR * 1.15;
  return { x: CX + rr * Math.sin(θ), y: CY - rr * Math.cos(θ) };
}

function reprojectTargets() {
  for (const t of radarTargets) t.pt = project(t.lat, t.lng);
}

function radarSetHome(lat, lon) {
  if (typeof lat !== 'number' || typeof lon !== 'number') return;
  homeLat = lat; homeLon = lon;
  reprojectTargets();
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
      const tk = clientTrafficKey(c.protocol, c.localAddress, c.localPort, c.remoteAddress, c.remotePort);
      const live = liveTraffic.get(tk);
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
  requestAnimationFrame(radarFrame);
  if (!radarOn) return;
  if (!lastT) lastT = ts;
  const dt = (ts - lastT) / 1000; lastT = ts;
  sweepAngle += dt * (Math.PI * 2 / 7);
  if (sweepAngle > Math.PI) sweepAngle -= Math.PI * 2;

  const ctx = radarCtx;
  ctx.clearRect(0, 0, RW, RH);
  if (RR <= 0) return;

  // vignette
  const g = ctx.createRadialGradient(CX, CY, RR * 0.1, CX, CY, RR * 1.1);
  g.addColorStop(0, 'rgba(255,255,255,0.02)');
  g.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = g; ctx.fillRect(0, 0, RW, RH);

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
requestAnimationFrame(radarFrame);

// ---------- System health (live from /api/system-health) ----------
function fmtBytes(n) {
  if (n == null) return '—';
  const gb = n / (1024 ** 3);
  return gb >= 1 ? gb.toFixed(1) + ' GB' : (n / (1024 ** 2)).toFixed(0) + ' MB';
}
async function refreshSystemHealth() {
  try {
    const res = await fetch('/api/system-health');
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
    if (h.tempC == null) {
      hTemp.textContent = '—';
      hTempbar.style.width = '0%';
    } else {
      hTemp.textContent = h.tempC.toFixed(0) + ' °C';
      hTempbar.style.width = Math.min(100, h.tempC).toFixed(0) + '%';
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
