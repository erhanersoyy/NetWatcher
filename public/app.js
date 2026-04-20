// DOM refs
const appEl = document.getElementById('app');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const processCountEl = document.getElementById('processCount');
const connectionCountEl = document.getElementById('connectionCount');
const globeContainer = document.getElementById('globeContainer');

// Filter refs
const filterIPv6 = document.getElementById('filterIPv6');
const filterPrivate = document.getElementById('filterPrivate');
const filterLocalhost = document.getElementById('filterLocalhost');
const filterSystem = document.getElementById('filterSystem');
const searchInput = document.getElementById('searchInput');
const sortSelect = document.getElementById('sortSelect');
const expandAllBtn = document.getElementById('expandAllBtn');
const collapseAllBtn = document.getElementById('collapseAllBtn');
const refreshNowBtn = document.getElementById('refreshNowBtn');
const refreshSelect = document.getElementById('refreshSelect');
const blockedListBtn = document.getElementById('blockedListBtn');

// State
const expandedPids = new Set();
let lastData = null;
let hostInfo = null;
let myGlobe = null;
let blockedIPs = new Set();
let refreshTimer = null;
let refreshIntervalMs = 2000;

const OPACITY = 0.3;

// --- Helpers ---

function flag(code) {
  if (!code || code === 'LO' || code === '??') return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function isIPv6(addr) { return addr.includes(':'); }

function isPrivateIP(addr) {
  if (addr.startsWith('10.') || addr.startsWith('192.168.') || addr.startsWith('127.')) return true;
  if (addr === '0.0.0.0' || addr === '::' || addr === '::1' || addr.startsWith('169.254.') || addr.startsWith('fe80:')) return true;
  const lower = addr.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.slice(7);
    if (v4.includes('.')) return isPrivateIP(v4);
  }
  if (addr.startsWith('172.')) {
    const second = parseInt(addr.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  if (addr.startsWith('100.')) {
    const second = parseInt(addr.split('.')[1], 10);
    if (second >= 64 && second <= 127) return true;
  }
  if (/^f[cd][0-9a-f]{2}:/i.test(addr)) return true;
  return false;
}

const CSRF_HEADER = { 'x-requested-by': 'netwatcher' };

function isLocalhost(addr) {
  return addr === '127.0.0.1' || addr === '::1' || addr.startsWith('127.');
}

// --- Sorting ---

function sortProcesses(processes) {
  const mode = sortSelect.value;
  return [...processes].sort((a, b) => {
    if (mode === 'pid') return a.pid - b.pid;
    if (mode === 'name') return a.processName.localeCompare(b.processName);
    return b.connections.length - a.connections.length; // connections (default)
  });
}

// --- Filtering ---

function applyFilters(processes) {
  const exIPv6 = filterIPv6.checked;
  const exPriv = filterPrivate.checked;
  const exLocal = filterLocalhost.checked;
  const hideSystem = filterSystem.checked;
  const search = searchInput.value.toLowerCase().trim();

  return processes
    .filter(proc => !(hideSystem && proc.isSystemProcess))
    .map(proc => {
      const filtered = proc.connections.filter(conn => {
        if (exIPv6 && isIPv6(conn.remoteAddress)) return false;
        if (exPriv && isPrivateIP(conn.remoteAddress)) return false;
        if (exLocal && isLocalhost(conn.remoteAddress)) return false;
        if (search) {
          const haystack = `${proc.processName} ${conn.remoteAddress} ${conn.domain || ''} ${conn.geo?.country || ''} ${conn.geo?.isp || ''} ${conn.geo?.city || ''}`.toLowerCase();
          if (!haystack.includes(search)) return false;
        }
        return true;
      });
      return { ...proc, connections: filtered };
    }).filter(proc => proc.connections.length > 0);
}

// --- Render ---

function renderProcess(proc) {
  const isExpanded = expandedPids.has(proc.pid);

  const descTooltip = escapeHtml(proc.description || 'Unknown process');
  const infoBadge = `<span class="info-badge" title="${descTooltip}">?</span>`;

  const cautionBadge = proc.isSystemProcess
    ? '<span class="caution-badge" title="System process - killing may affect system stability">&#9888;</span>'
    : '';

  const killBtnClass = proc.isSystemProcess ? 'kill-btn kill-btn-system' : 'kill-btn';
  const killBtnAttrs = `data-action="kill" data-pid="${proc.pid}" data-name="${escapeHtml(proc.processName)}" data-system="${proc.isSystemProcess ? '1' : '0'}"`;

  let connectionsHtml = '';
  if (isExpanded) {
    const rows = proc.connections.map(conn => {
      const geo = conn.geo;
      let geoCountry = '<span class="geo-unknown">Resolving...</span>';
      let geoIsp = '<span class="geo-unknown">-</span>';

      if (geo) {
        if (geo.country === 'Local') {
          geoCountry = 'Local';
          geoIsp = 'Private Network';
        } else {
          const f = flag(geo.countryCode);
          const city = geo.city ? `${escapeHtml(geo.city)}, ` : '';
          geoCountry = `<span class="flag">${f}</span>${city}${escapeHtml(geo.country)}`;
          geoIsp = escapeHtml(geo.isp);
        }
      }

      const domain = conn.domain && conn.domain !== '-'
        ? `<span class="domain-name">${escapeHtml(conn.domain)}</span>`
        : '<span class="geo-unknown">-</span>';

      const ipEsc = escapeHtml(conn.remoteAddress);
      const showVt = !isPrivateIP(conn.remoteAddress) && !isLocalhost(conn.remoteAddress);
      const vtBtn = showVt
        ? `<button class="vt-btn" data-action="vt" data-ip="${ipEsc}" title="VirusTotal reputation check">VT</button>`
        : '<span class="geo-unknown">-</span>';

      // Blocked status + block/unblock button
      const isBlocked = blockedIPs.has(conn.remoteAddress);
      const blockedTag = isBlocked ? '<span class="blocked-tag">BLOCKED</span>' : '';
      const canBlock = !isPrivateIP(conn.remoteAddress) && !isLocalhost(conn.remoteAddress);
      let blockBtn = '';
      if (canBlock) {
        if (isBlocked) {
          blockBtn = `<button class="unblock-btn" data-action="unblock" data-ip="${ipEsc}" title="Unblock IP in firewall">Unblock</button>`;
        } else {
          blockBtn = `<button class="block-btn" data-action="block" data-ip="${ipEsc}" title="Block IP in firewall">Block</button>`;
        }
      }

      return `<tr class="${isBlocked ? 'row-blocked' : ''}">
        <td>${escapeHtml(conn.protocol)}</td>
        <td>${escapeHtml(conn.remoteAddress)} ${blockedTag}</td>
        <td>${conn.remotePort}</td>
        <td>${domain}</td>
        <td>${geoCountry}</td>
        <td>${geoIsp}</td>
        <td>${vtBtn}</td>
        <td>${blockBtn}</td>
      </tr>`;
    }).join('');

    connectionsHtml = `<div class="connections-table">
      <table>
        <thead><tr>
          <th>Proto</th><th>Remote IP</th><th>Port</th><th>Domain</th><th>Location</th><th>ISP</th><th>Rep.</th><th>Firewall</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }

  return `<div class="process-card ${isExpanded ? 'expanded' : ''} ${proc.isSystemProcess ? 'system-process' : ''}" data-pid="${proc.pid}">
    <div class="process-header" data-action="toggle" data-pid="${proc.pid}">
      <span class="expand-icon">&#9654;</span>
      ${cautionBadge}
      <span class="process-name">${escapeHtml(proc.processName)}</span>
      ${infoBadge}
      <span class="process-pid">PID ${proc.pid}</span>
      <span class="conn-count">${proc.connections.length}</span>
      <button class="${killBtnClass}" ${killBtnAttrs}>Kill</button>
    </div>
    ${connectionsHtml}
  </div>`;
}

function render(processes) {
  const filtered = applyFilters(processes);
  const sorted = sortProcesses(filtered);
  const totalConnections = sorted.reduce((sum, p) => sum + p.connections.length, 0);
  processCountEl.textContent = `${sorted.length} process${sorted.length !== 1 ? 'es' : ''}`;
  connectionCountEl.textContent = `${totalConnections} connection${totalConnections !== 1 ? 's' : ''}`;

  if (sorted.length === 0) {
    appEl.innerHTML = '<div class="no-connections">No connections match current filters</div>';
  } else {
    appEl.innerHTML = sorted.map(renderProcess).join('');
  }

  updateGlobe(sorted);
}

// --- Globe: matching highlight-links example pattern ---

function initGlobe() {
  myGlobe = new Globe(globeContainer)
    .globeImageUrl('//cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg')
    .bumpImageUrl('//cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png')
    .backgroundImageUrl('//cdn.jsdelivr.net/npm/three-globe/example/img/night-sky.png')
    .width(globeContainer.clientWidth)
    .height(globeContainer.clientHeight)
    .atmosphereColor('#58a6ff')
    .atmosphereAltitude(0.15)
    .pointColor('color')
    .pointAltitude(0)
    .pointRadius('radius')
    .pointsMerge(true)
    .arcLabel(d => `<div class="globe-tooltip">${d.label}</div>`)
    .arcStartLat('startLat')
    .arcStartLng('startLng')
    .arcEndLat('endLat')
    .arcEndLng('endLng')
    .arcColor(d => [`rgba(88, 166, 255, ${OPACITY})`, `rgba(249, 115, 22, ${OPACITY})`])
    .arcDashLength(0.4)
    .arcDashGap(0.2)
    .arcDashAnimateTime(1500)
    .onArcHover(hoverArc => myGlobe
      .arcColor(d => {
        const op = !hoverArc ? OPACITY : d === hoverArc ? 0.9 : OPACITY / 4;
        return [`rgba(88, 166, 255, ${op})`, `rgba(249, 115, 22, ${op})`];
      })
    );

  const legend = document.createElement('div');
  legend.className = 'globe-legend';
  legend.innerHTML = `
    <div class="globe-legend-item"><span class="legend-dot home"></span> Your location</div>
    <div class="globe-legend-item"><span class="legend-dot dest"></span> Remote destination</div>
  `;
  globeContainer.appendChild(legend);

  const ro = new ResizeObserver(() => {
    if (myGlobe) myGlobe.width(globeContainer.clientWidth).height(globeContainer.clientHeight);
  });
  ro.observe(globeContainer);
}

function updateGlobe(filteredProcesses) {
  if (!myGlobe) return;

  const points = [];
  const arcs = [];
  const seenPins = new Set();
  const seenArcs = new Set();

  let homeLat = 0, homeLon = 0;
  if (hostInfo?.geo) {
    homeLat = hostInfo.geo.lat;
    homeLon = hostInfo.geo.lon;
    points.push({ lat: homeLat, lng: homeLon, radius: 0.6, color: '#58a6ff' });
  }

  for (const proc of filteredProcesses) {
    for (const conn of proc.connections) {
      const geo = conn.geo;
      if (!geo || geo.country === 'Local' || (!geo.lat && !geo.lon)) continue;

      const pinKey = `${geo.lat.toFixed(2)},${geo.lon.toFixed(2)}`;
      if (!seenPins.has(pinKey)) {
        seenPins.add(pinKey);
        points.push({ lat: geo.lat, lng: geo.lon, radius: 0.35, color: '#f97316' });
      }

      if (homeLat || homeLon) {
        const arcKey = `${homeLat},${homeLon}->${pinKey}`;
        if (!seenArcs.has(arcKey)) {
          seenArcs.add(arcKey);
          const domainStr = conn.domain && conn.domain !== '-' ? ` (${escapeHtml(conn.domain)})` : '';
          arcs.push({
            startLat: homeLat, startLng: homeLon,
            endLat: geo.lat, endLng: geo.lon,
            label: `${escapeHtml(proc.processName)} &#8594; ${escapeHtml(conn.remoteAddress)}${domainStr}<br>${geo.city ? escapeHtml(geo.city) + ', ' : ''}${escapeHtml(geo.country)}`,
          });
        }
      }
    }
  }

  myGlobe.pointsData(points).arcsData(arcs);
}

// --- Blocked IPs ---

async function fetchBlockedIPs() {
  try {
    const res = await fetch('/api/blocked');
    if (!res.ok) return;
    const ips = await res.json();
    blockedIPs = new Set(ips);
  } catch { /* ignore */ }
}

async function sendFirewallRequest(path, ip, password) {
  // Send password to local backend (127.0.0.1 only). The value lives in this
  // function scope; after the body is serialized we overwrite the local ref.
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
        if (lastData) render(lastData);
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
        if (lastData) render(lastData);
      }
    } catch (err) {
      showToast('Failed to unblock IP: ' + err.message, 'error');
    }
  });
}

// --- VirusTotal ---

async function vtCheckAction(ip) {
  showVtModal(ip, 'Loading VirusTotal data...');
  try {
    const res = await fetch(`/api/vt/${encodeURIComponent(ip)}`);
    const data = await res.json();
    showVtModal(ip, data.output, data.success);
  } catch (err) {
    showVtModal(ip, 'Failed to reach VT endpoint: ' + err.message, false);
  }
}

function showVtModal(ip, content, success) {
  const existing = document.getElementById('vtOverlay');
  if (existing) existing.remove();

  const formattedContent = formatVtOutput(content, success);
  const overlay = document.createElement('div');
  overlay.id = 'vtOverlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="vt-modal">
      <div class="vt-modal-header">
        <span class="vt-modal-title">VirusTotal: ${escapeHtml(ip)}</span>
        <button class="vt-modal-close">&times;</button>
      </div>
      <div class="vt-modal-body">${formattedContent}</div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('.vt-modal-close').addEventListener('click', () => overlay.remove());
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

function formatVtOutput(raw, success) {
  if (success === undefined) return `<div class="vt-loading">${escapeHtml(raw)}</div>`;
  if (!success) return `<pre class="vt-output vt-error">${escapeHtml(raw)}</pre>`;

  const lines = raw.split('\n');
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

// --- Host Info ---

async function fetchHostInfo({ fresh } = { fresh: false }) {
  try {
    const res = await fetch('/api/host-info' + (fresh ? '?fresh=1' : ''));
    if (!res.ok) return;
    hostInfo = await res.json();

    document.getElementById('hostHostname').textContent = hostInfo.hostname;
    document.getElementById('hostLocalIP').textContent = hostInfo.localIP;
    document.getElementById('hostPublicIP').textContent = hostInfo.publicIP;

    if (hostInfo.geo) {
      const city = hostInfo.geo.city ? escapeHtml(hostInfo.geo.city) + ', ' : '';
      const f = flag(hostInfo.geo.countryCode);
      document.getElementById('hostLocation').innerHTML = `${f} ${city}${escapeHtml(hostInfo.geo.country)}`;
      document.getElementById('hostISP').textContent = hostInfo.geo.isp;

      if (myGlobe && hostInfo.geo.lat && hostInfo.geo.lon) {
        myGlobe.pointOfView({ lat: hostInfo.geo.lat, lng: hostInfo.geo.lon, altitude: 2.5 }, 4000);
      }
    }
  } catch { /* ignore */ }
}

// --- Data fetching ---

async function fetchConnections() {
  try {
    const res = await fetch('/api/connections');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    lastData = data;

    statusDot.className = 'status-dot connected';
    statusText.textContent = 'Live';

    render(data);
  } catch (err) {
    statusDot.className = 'status-dot error';
    statusText.textContent = 'Error: ' + err.message;
  }
}

// --- Actions ---

function toggleProcess(pid) {
  if (expandedPids.has(pid)) expandedPids.delete(pid);
  else expandedPids.add(pid);
  if (lastData) render(lastData);
}

function expandAll() {
  if (!lastData) return;
  const filtered = applyFilters(lastData);
  for (const proc of filtered) expandedPids.add(proc.pid);
  render(lastData);
}

function collapseAll() {
  expandedPids.clear();
  if (lastData) render(lastData);
}

function killProcessAction(pid, name, isSystem) {
  if (isSystem) {
    showConfirmDialog(
      `"${name}" is a system process required for system stability. Are you sure you want to kill it?`,
      () => doKill(pid)
    );
    return;
  }
  doKill(pid);
}

async function doKill(pid) {
  const btn = document.querySelector(`.process-card[data-pid="${pid}"] .kill-btn`);
  if (btn) { btn.classList.add('killing'); btn.textContent = 'Killing...'; }
  try {
    const res = await fetch(`/api/kill/${pid}`, { method: 'POST', headers: CSRF_HEADER });
    const result = await res.json();
    showToast(result.message, result.success ? 'success' : 'error');
    setTimeout(fetchConnections, 500);
  } catch (err) {
    showToast('Failed to kill process: ' + err.message, 'error');
  }
}

appEl.addEventListener('click', (e) => {
  const target = e.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  if (action === 'toggle') {
    toggleProcess(parseInt(target.dataset.pid, 10));
    return;
  }
  e.stopPropagation();
  if (action === 'kill') {
    killProcessAction(parseInt(target.dataset.pid, 10), target.dataset.name, target.dataset.system === '1');
  } else if (action === 'vt') {
    vtCheckAction(target.dataset.ip);
  } else if (action === 'block') {
    blockIPAction(target.dataset.ip);
  } else if (action === 'unblock') {
    unblockIPAction(target.dataset.ip);
  }
});

function showConfirmDialog(message, onConfirm) {
  const existing = document.getElementById('confirmOverlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'confirmOverlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="confirm-dialog">
      <div class="confirm-icon">&#9888;</div>
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

async function showBlockedListModal() {
  const existing = document.getElementById('blockedListOverlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'blockedListOverlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="blocked-modal">
      <div class="vt-modal-header">
        <span class="vt-modal-title">Blocked IPs</span>
        <button class="vt-modal-close" data-close="1">&times;</button>
      </div>
      <div class="blocked-modal-body"><div class="vt-loading">Loading…</div></div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay || e.target.dataset.close === '1') overlay.remove();
  });

  let data;
  try {
    const res = await fetch('/api/block-history');
    data = await res.json();
  } catch (err) {
    overlay.querySelector('.blocked-modal-body').innerHTML =
      `<div class="vt-output vt-error">Failed to load: ${escapeHtml(err.message)}</div>`;
    return;
  }

  const rows = buildBlockedRows(data.history || []);
  const body = overlay.querySelector('.blocked-modal-body');
  if (rows.length === 0) {
    body.innerHTML = '<div class="blocked-empty">No blocks recorded yet.</div>';
    return;
  }

  body.innerHTML = `
    <table class="blocked-table">
      <thead><tr>
        <th>IP</th><th>Country</th><th>Blocked At</th><th>Status</th>
      </tr></thead>
      <tbody>${rows.map(r => `
        <tr>
          <td><code>${escapeHtml(r.ip)}</code></td>
          <td>${r.country ? escapeHtml(r.country) : '<span class="geo-unknown">-</span>'}</td>
          <td>${escapeHtml(formatTime(r.blockedAt))}</td>
          <td>${r.status === 'active'
            ? '<span class="blocked-tag">ACTIVE</span>'
            : `<span class="geo-unknown">Unblocked ${escapeHtml(formatTime(r.unblockedAt))}</span>`}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  `;
}

// Pair each 'block' event with the next 'unblock' event for the same IP
// so every row represents one block session (active or closed).
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
        if (pending) {
          // Two blocks in a row without an unblock — treat first as lost/closed.
          rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'unblocked', unblockedAt: pending.at });
        }
        pending = ev;
      } else if (ev.action === 'unblock' && pending) {
        rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'unblocked', unblockedAt: ev.at });
        pending = null;
      }
    }
    if (pending) {
      rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'active' });
    }
  }
  rows.sort((a, b) => b.blockedAt - a.blockedAt);
  return rows;
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function askSudoPassword(action, ip, onSubmit) {
  const existing = document.getElementById('sudoOverlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'sudoOverlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="confirm-dialog sudo-dialog">
      <div class="confirm-icon">&#9888;</div>
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
    // Overwrite then clear the input value before removing it from the DOM.
    input.value = '';
    overlay.remove();
    return pwd;
  };
  const cancel = () => { cleanup(false); };
  const submit = () => {
    const pwd = cleanup(true);
    onSubmit(pwd);
  };

  overlay.querySelector('.confirm-cancel').addEventListener('click', cancel);
  overlay.querySelector('.sudo-submit').addEventListener('click', submit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
    else if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) cancel(); });
}

function showToast(message, type) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// --- Event listeners ---
[filterIPv6, filterPrivate, filterLocalhost, filterSystem].forEach(el => {
  el.addEventListener('change', () => { if (lastData) render(lastData); });
});

sortSelect.addEventListener('change', () => { if (lastData) render(lastData); });
expandAllBtn.addEventListener('click', () => expandAll());
collapseAllBtn.addEventListener('click', () => collapseAll());

let searchTimeout;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => { if (lastData) render(lastData); }, 200);
});

// --- Refresh orchestration ---

async function refreshAll({ fresh } = { fresh: false }) {
  // Run independent fetches in parallel. Host info bypasses its server-side cache
  // only when the user explicitly asked for a fresh pull.
  await Promise.all([
    fetchConnections(),
    fetchHostInfo({ fresh }),
    fetchBlockedIPs(),
  ]);
}

function scheduleRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (refreshIntervalMs > 0) {
    refreshTimer = setInterval(() => { refreshAll({ fresh: false }); }, refreshIntervalMs);
  }
}

refreshSelect.addEventListener('change', () => {
  refreshIntervalMs = parseInt(refreshSelect.value, 10) || 2000;
  scheduleRefresh();
});

refreshNowBtn.addEventListener('click', async () => {
  refreshNowBtn.classList.add('spinning');
  try {
    await refreshAll({ fresh: true });
  } finally {
    refreshNowBtn.classList.remove('spinning');
  }
});

blockedListBtn.addEventListener('click', () => showBlockedListModal());

// --- Init ---
initGlobe();
refreshAll({ fresh: true });
scheduleRefresh();
