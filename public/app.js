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
const filterSystem = document.getElementById('filterSystem');
const searchInput = document.getElementById('searchInput');
const sortSelect = document.getElementById('sortSelect');
const expandAllBtn = document.getElementById('expandAllBtn');
const collapseAllBtn = document.getElementById('collapseAllBtn');
const refreshNowBtn = document.getElementById('refreshNowBtn');
const refreshSelect = document.getElementById('refreshSelect');
const blockedListBtn = document.getElementById('blockedListBtn');
const listToggleBtn = document.getElementById('listToggleBtn');

// State
const expandedPids = new Set();
let lastData = null;
let hostInfo = null;
let myGlobe = null;
let blockedIPs = new Set();
let refreshTimer = null;
// Default 5m — the select is initialised with matching `selected` attr on
// the same option, so DOM + state stay aligned.
let refreshIntervalMs = 300000;
// Cached fingerprint of the last globe payload — skip the geometry rebuild
// (which freezes mouse drag/zoom mid-animation) when nothing has changed.
let lastGlobeFingerprint = '';
// When the user is actively dragging/zooming the globe, defer updates. Any
// pointsData/arcsData call while interacting interrupts the gesture and the
// globe appears to "stick". We queue the latest payload and apply it once
// the pointer releases.
let globeInteracting = false;
let pendingGlobePayload = null;
// Last rendered (post-filter, post-sort) process list. The animation loop
// reuses this to trigger a geometry reconcile when a pin ages out of its
// lifecycle without a new poll having arrived.
let lastFilteredProcesses = [];

// --- New globe feature state ---
// Track pin/arc lifecycles across refreshes for flash/dissolve animations.
// Keys are stable identifiers (pinKey for pins, arcKey for arcs). Values
// carry birth time and current lifecycle phase ('new' | 'live' | 'dying').
const pinLifecycle = new Map();  // pinKey -> { birth, phase, deathStarted? }
const arcLifecycle = new Map();  // arcKey -> { birth, phase, deathStarted? }
// Rolling bandwidth per destination pin for the Top Talkers panel. We store
// the most recent sum(bytesIn + bytesOut) seen on any connection to that pin.
const pinBandwidth = new Map();  // pinKey -> { lat, lng, country, bytes, lastBump }
// Per-connection cumulative byte snapshot from the previous frame. Used to
// detect *real* activity on a pin: we sum positive deltas across connections
// instead of comparing pin-level totals (which can stay flat or even decrease
// when one connection closes while another opens to the same pin).
const prevConnBytes = new Map(); // connId -> bytes
// PID currently hovered on the left panel — arcs/pins belonging to other
// processes dim to "ghost" mode while this is set.
let hoveredPid = null;
// Remote IP focused via globe pin click (auto-fills search). Null = unfocused.
let focusedPinLabel = null;

const BASE_OPACITY = 0.3;
const DIM_OPACITY = 0.08;        // everything not owned by the hovered process
const HIGHLIGHT_OPACITY = 0.95;  // owned arcs during hover
const FLASH_DURATION_MS = 900;
const DYING_DURATION_MS = 550;
const ANIM_FPS = 30;

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

function formatBytes(n) {
  if (n === undefined || n === null || isNaN(n)) return '-';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

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
  const hideSystem = filterSystem.checked;
  const search = searchInput.value.toLowerCase().trim();

  return processes
    .filter(proc => !(hideSystem && proc.isSystemProcess))
    .map(proc => {
      const filtered = proc.connections.filter(conn => {
        if (exIPv6 && isIPv6(conn.remoteAddress)) return false;
        if (exPriv && isPrivateIP(conn.remoteAddress)) return false;
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

      const rxCell = conn.bytesIn !== undefined
        ? `<span class="bytes-cell bytes-rx" title="${conn.bytesIn} bytes received">${formatBytes(conn.bytesIn)}</span>`
        : '<span class="geo-unknown">-</span>';
      const txCell = conn.bytesOut !== undefined
        ? `<span class="bytes-cell bytes-tx" title="${conn.bytesOut} bytes sent">${formatBytes(conn.bytesOut)}</span>`
        : '<span class="geo-unknown">-</span>';

      return `<tr class="${isBlocked ? 'row-blocked' : ''}">
        <td>${escapeHtml(conn.protocol)}</td>
        <td>${escapeHtml(conn.remoteAddress)} ${blockedTag}</td>
        <td>${conn.remotePort}</td>
        <td>${domain}</td>
        <td class="bytes-col">${rxCell}</td>
        <td class="bytes-col">${txCell}</td>
        <td>${geoCountry}</td>
        <td>${geoIsp}</td>
        <td>${vtBtn}</td>
        <td>${blockBtn}</td>
      </tr>`;
    }).join('');

    connectionsHtml = `<div class="connections-table">
      <table>
        <thead><tr>
          <th>Proto</th><th>Remote IP</th><th>Port</th><th>Domain</th><th class="bytes-col">&#8595; RX</th><th class="bytes-col">&#8593; TX</th><th>Location</th><th>ISP</th><th>Rep.</th><th>Firewall</th>
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
  const newProcessText = `${sorted.length} process${sorted.length !== 1 ? 'es' : ''}`;
  const newConnText = `${totalConnections} connection${totalConnections !== 1 ? 's' : ''}`;
  if (processCountEl.textContent !== newProcessText) {
    processCountEl.textContent = newProcessText;
    flickerCounter(processCountEl);
  }
  if (connectionCountEl.textContent !== newConnText) {
    connectionCountEl.textContent = newConnText;
    flickerCounter(connectionCountEl);
  }

  if (sorted.length === 0) {
    appEl.innerHTML = '<div class="no-connections">No connections match current filters</div>';
  } else {
    appEl.innerHTML = sorted.map(renderProcess).join('');
  }

  lastFilteredProcesses = sorted;
  updateGlobe(sorted);
  renderTopTalkers();
}

// --- Globe: matching highlight-links example pattern ---

function initGlobe() {
  myGlobe = new Globe(globeContainer)
    .globeImageUrl('//cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg')
    .bumpImageUrl('//cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png')
    .backgroundImageUrl('//cdn.jsdelivr.net/npm/three-globe/example/img/night-sky.png')
    .width(globeContainer.clientWidth)
    .height(globeContainer.clientHeight)
    // Neon cyan — the rAF loop keeps this hue locked and pulses altitude only.
    .atmosphereColor('#57d8ff')
    .atmosphereAltitude(0.15)
    // Country borders (GeoJSON loaded async below). Caps/sides kept transparent
    // so only the edges show — the earth texture stays visible underneath.
    .polygonsData([])
    .polygonCapColor(() => 'rgba(0, 0, 0, 0)')
    .polygonSideColor(() => 'rgba(0, 0, 0, 0)')
    .polygonStrokeColor(() => 'rgba(87, 216, 255, 0.55)')
    .polygonAltitude(0.006)
    .pointColor('color')
    .pointAltitude(0)
    .pointRadius('radius')
    .pointsMerge(false) // needed so individual pins can flash/dissolve independently
    .pointLabel(d => d.label ? `<div class="globe-tooltip">${d.label}</div>` : '')
    .onPointClick(pt => {
      if (!pt || !pt.pinLabel) return;
      // Toggle off if clicking the same pin again.
      if (focusedPinLabel === pt.pinLabel) {
        focusedPinLabel = null;
        searchInput.value = '';
      } else {
        focusedPinLabel = pt.pinLabel;
        searchInput.value = pt.pinLabel;
      }
      if (lastData) render(lastData);
    })
    .arcLabel(d => `<div class="globe-tooltip">${d.label}</div>`)
    .arcStartLat('startLat')
    .arcStartLng('startLng')
    .arcEndLat('endLat')
    .arcEndLng('endLng')
    .arcColor(arcColorFn)
    .arcStroke(d => d.stroke ?? 0.4)
    .arcDashLength(0.4)
    .arcDashGap(0.2)
    .arcDashAnimateTime(1500)
    .onArcHover(hoverArc => {
      myGlobe.arcColor(d => arcColorFn(d, hoverArc));
    });

  // Render a translucent legend overlay in the bottom-left.
  const legend = document.createElement('div');
  legend.className = 'globe-legend';
  legend.innerHTML = `
    <div class="globe-legend-item"><span class="legend-dot home"></span> Your location</div>
    <div class="globe-legend-item"><span class="legend-dot dest"></span> Remote destination</div>
    <div class="globe-legend-item"><span class="legend-dot new"></span> New connection</div>
    <div class="globe-legend-item"><span class="legend-dot dying"></span> Closing</div>
  `;
  globeContainer.appendChild(legend);

  // Top Talkers overlay — populated by renderTopTalkers().
  const talkers = document.createElement('div');
  talkers.className = 'globe-talkers';
  talkers.id = 'globeTalkers';
  talkers.innerHTML = `
    <div class="talkers-header">TOP TALKERS</div>
    <div class="talkers-list" id="talkersList">
      <div class="talkers-empty">–– no traffic ––</div>
    </div>
  `;
  globeContainer.appendChild(talkers);

  // Clear focused pin when clicking empty space on the globe.
  globeContainer.addEventListener('click', (e) => {
    // Only treat as "empty space" clicks that don't bubble from the HTML overlays.
    if (e.target === globeContainer || e.target.tagName === 'CANVAS') {
      if (focusedPinLabel) {
        focusedPinLabel = null;
        searchInput.value = '';
        if (lastData) render(lastData);
      }
    }
  });

  const ro = new ResizeObserver(() => {
    if (myGlobe) myGlobe.width(globeContainer.clientWidth).height(globeContainer.clientHeight);
  });
  ro.observe(globeContainer);

  // Track pointer interaction on the globe's own canvas so live refreshes
  // don't interrupt a drag/zoom gesture. Releasing flushes the latest payload.
  const beginInteract = () => { globeInteracting = true; };
  const endInteract = () => {
    globeInteracting = false;
    if (pendingGlobePayload) {
      const { points, arcs, fingerprint } = pendingGlobePayload;
      pendingGlobePayload = null;
      lastGlobeFingerprint = fingerprint;
      myGlobe.pointsData(points).arcsData(arcs);
    }
  };
  globeContainer.addEventListener('pointerdown', beginInteract);
  // Listen on window so releases outside the container still clear the flag.
  window.addEventListener('pointerup', endInteract);
  window.addEventListener('pointercancel', endInteract);
  // Wheel zoom: brief pause while wheel events are arriving.
  let wheelTimer = null;
  globeContainer.addEventListener('wheel', () => {
    beginInteract();
    clearTimeout(wheelTimer);
    wheelTimer = setTimeout(endInteract, 250);
  }, { passive: true });

  // Fetch country borders (non-blocking — the globe renders fine without them).
  // Using jsdelivr's GitHub mirror of the three-globe example dataset.
  loadCountryBorders();

  // Drive the atmosphere pulse + lifecycle animations at ~30fps.
  startGlobeAnimationLoop();
}

async function loadCountryBorders() {
  const sources = [
    'https://cdn.jsdelivr.net/gh/vasturiano/three-globe@master/example/country-polygons/ne_110m_admin_0_countries.geojson',
    'https://raw.githubusercontent.com/vasturiano/three-globe/master/example/country-polygons/ne_110m_admin_0_countries.geojson',
  ];
  for (const url of sources) {
    try {
      const res = await fetch(url);
      if (!res.ok) continue;
      const data = await res.json();
      const features = Array.isArray(data?.features) ? data.features : [];
      if (features.length && myGlobe) myGlobe.polygonsData(features);
      return;
    } catch { /* try next source */ }
  }
}

// Compute arc color respecting hover state, hovered process dim, and lifecycle.
function arcColorFn(d, hoverArc) {
  const lifecycle = arcLifecycle.get(d.arcKey);
  let op = BASE_OPACITY;

  // Lifecycle: brighten new arcs, fade dying arcs.
  if (lifecycle) {
    const now = performance.now();
    if (lifecycle.phase === 'new') {
      const age = now - lifecycle.birth;
      const t = Math.max(0, 1 - age / FLASH_DURATION_MS);
      op = BASE_OPACITY + (HIGHLIGHT_OPACITY - BASE_OPACITY) * t;
    } else if (lifecycle.phase === 'dying') {
      const age = now - lifecycle.deathStarted;
      const t = Math.max(0, 1 - age / DYING_DURATION_MS);
      op = BASE_OPACITY * t;
    }
  }

  // Process-hover dim: non-owned arcs get pushed way down.
  if (hoveredPid != null && d.pid !== hoveredPid) {
    op = Math.min(op, DIM_OPACITY);
  } else if (hoveredPid != null && d.pid === hoveredPid) {
    op = Math.max(op, 0.7);
  }

  // onArcHover emphasis wins over everything else for the hovered arc.
  if (hoverArc) {
    op = d === hoverArc ? 0.95 : Math.min(op, DIM_OPACITY);
  }

  return [`rgba(88, 166, 255, ${op})`, `rgba(249, 115, 22, ${op})`];
}

// Compute per-point color, with lifecycle flash and dissolve glitch applied.
function pointColorFn(d) {
  const now = performance.now();
  const lifecycle = pinLifecycle.get(d.pinKey);

  // Home pin is always cyan.
  if (d.kind === 'home') return '#58a6ff';

  // New-pin flash: fade from near-white → neon green → orange base color.
  if (lifecycle?.phase === 'new') {
    const age = now - lifecycle.birth;
    const t = Math.min(1, age / FLASH_DURATION_MS);
    // 0.0 → 0.35: white-hot (#ffffff)
    // 0.35 → 0.7: neon green (#39ff14)
    // 0.7 → 1.0: settle to orange (#f97316)
    if (t < 0.35) return '#ffffff';
    if (t < 0.7)  return '#39ff14';
    return '#f97316';
  }

  // Closing-pin glitch: chromatic flicker between magenta and red, then fade to transparent.
  if (lifecycle?.phase === 'dying') {
    const age = now - lifecycle.deathStarted;
    const t = Math.min(1, age / DYING_DURATION_MS);
    // Fast flip between two colors for a glitch feel.
    const blink = Math.floor(t * 8) % 2 === 0;
    return blink ? '#ff2bd6' : '#f85149';
  }

  // Process hover dim.
  if (hoveredPid != null) {
    // If any connection for this pin belongs to the hovered process, keep bright.
    // (Pins can be shared by multiple processes; d.pids is populated in updateGlobe.)
    if (d.pids && d.pids.has(hoveredPid)) return '#f97316';
    return '#30363d';
  }

  return '#f97316';
}

function updateGlobe(filteredProcesses) {
  if (!myGlobe) return;

  const points = [];
  const arcs = [];
  const seenPins = new Map();   // pinKey -> pin object (so we can merge pids)
  const seenArcs = new Set();
  const currentPinKeys = new Set();
  const currentArcKeys = new Set();
  const now = performance.now();

  let homeLat = 0, homeLon = 0;
  if (hostInfo?.geo) {
    homeLat = hostInfo.geo.lat;
    homeLon = hostInfo.geo.lon;
    points.push({
      kind: 'home',
      pinKey: '__home__',
      lat: homeLat,
      lng: homeLon,
      radius: 0.6,
      color: '#58a6ff',
    });
    currentPinKeys.add('__home__');
  }

  // Reset per-frame bandwidth accumulator for the top-talkers panel.
  const frameBandwidth = new Map(); // pinKey -> bytes this frame
  const framePositiveDelta = new Map(); // pinKey -> summed positive per-conn delta this frame
  const frameConnBytes = new Map(); // connId -> bytes (snapshot to swap into prevConnBytes at end)

  for (const proc of filteredProcesses) {
    for (const conn of proc.connections) {
      const geo = conn.geo;
      if (!geo || geo.country === 'Local' || (!geo.lat && !geo.lon)) continue;

      const pinKey = `${geo.lat.toFixed(2)},${geo.lon.toFixed(2)}`;
      const pinLabel = escapeHtml(geo.city || geo.country || conn.remoteAddress);

      if (!seenPins.has(pinKey)) {
        const countryRaw = [geo.city, geo.country].filter(Boolean).join(', ');
        const pin = {
          kind: 'dest',
          pinKey,
          pinLabel,
          lat: geo.lat,
          lng: geo.lon,
          radius: 0.35,
          color: '#f97316',
          pids: new Set([proc.pid]),
          label: `${geo.city ? escapeHtml(geo.city) + ', ' : ''}${escapeHtml(geo.country || '')}`,
          countryRaw,
        };
        seenPins.set(pinKey, pin);
        points.push(pin);
      } else {
        seenPins.get(pinKey).pids.add(proc.pid);
      }
      currentPinKeys.add(pinKey);

      // Accumulate bytes for top-talkers (use latest per-connection totals).
      const bytes = (conn.bytesIn || 0) + (conn.bytesOut || 0);
      frameBandwidth.set(pinKey, (frameBandwidth.get(pinKey) || 0) + bytes);

      // Per-connection delta detection for the spark/bump: a pin "bumps" when
      // at least one of its connections moved bytes since the previous frame.
      const connId = `${proc.pid}|${conn.localAddress || ''}|${conn.localPort || ''}|${conn.remoteAddress || ''}|${conn.remotePort || ''}`;
      const prev = prevConnBytes.get(connId);
      // Treat a previously-unseen connection carrying bytes as positive activity.
      // If bytes < prev (counter reset / connection reuse) we don't subtract.
      const delta = prev === undefined ? bytes : Math.max(0, bytes - prev);
      if (delta > 0) {
        framePositiveDelta.set(pinKey, (framePositiveDelta.get(pinKey) || 0) + delta);
      }
      frameConnBytes.set(connId, bytes);

      if (hostInfo?.geo) {
        const arcKey = `${proc.pid}:${homeLat},${homeLon}->${pinKey}`;
        if (!seenArcs.has(arcKey)) {
          seenArcs.add(arcKey);
          const domainStr = conn.domain && conn.domain !== '-' ? ` (${escapeHtml(conn.domain)})` : '';
          arcs.push({
            arcKey,
            pid: proc.pid,
            startLat: homeLat, startLng: homeLon,
            endLat: geo.lat, endLng: geo.lon,
            label: `${escapeHtml(proc.processName)} &#8594; ${escapeHtml(conn.remoteAddress)}${domainStr}<br>${geo.city ? escapeHtml(geo.city) + ', ' : ''}${escapeHtml(geo.country)}`,
          });
          currentArcKeys.add(arcKey);
        } else {
          currentArcKeys.add(arcKey);
        }
      }
    }
  }

  // --- Update bandwidth store for Top Talkers ---
  // Store raw (un-escaped) country; `renderTopTalkers` escapes at the sink.
  for (const [pinKey, bytes] of frameBandwidth) {
    const existing = pinBandwidth.get(pinKey);
    const pin = seenPins.get(pinKey);
    if (!pin) continue;
    const bumped = (framePositiveDelta.get(pinKey) || 0) > 0;
    pinBandwidth.set(pinKey, {
      lat: pin.lat,
      lng: pin.lng,
      country: pin.countryRaw,
      bytes,
      lastBump: bumped ? now : (existing?.lastBump || 0),
    });
  }
  // NOTE: pinBandwidth is pruned in the lifecycle cleanup below (in lockstep
  // with `pinLifecycle.delete`) so dying pins can still rehydrate from it.

  // Swap per-connection byte snapshot for next-frame delta computation.
  prevConnBytes.clear();
  for (const [connId, bytes] of frameConnBytes) prevConnBytes.set(connId, bytes);

  // --- Lifecycle bookkeeping: mark new pins/arcs, and start dying for gone ones. ---
  for (const pinKey of currentPinKeys) {
    if (!pinLifecycle.has(pinKey) && pinKey !== '__home__') {
      pinLifecycle.set(pinKey, { birth: now, phase: 'new', lastSeen: now });
    } else if (pinLifecycle.has(pinKey)) {
      const lc = pinLifecycle.get(pinKey);
      // Revive a pin that was dying before we finished removing it.
      if (lc.phase === 'dying') {
        pinLifecycle.set(pinKey, { birth: now, phase: 'new', lastSeen: now });
      } else {
        lc.lastSeen = now;
      }
    }
  }
  // Pins that were in lifecycle but not seen this frame: transition to dying.
  // The animation loop also does this decoupled from the poll cadence (so a
  // 10-minute refresh setting still animates closures shortly after they
  // actually happen).
  for (const pinKey of pinLifecycle.keys()) {
    if (!currentPinKeys.has(pinKey)) {
      const lc = pinLifecycle.get(pinKey);
      if (lc.phase !== 'dying') {
        pinLifecycle.set(pinKey, { ...lc, phase: 'dying', deathStarted: now });
      }
    }
  }
  for (const arcKey of currentArcKeys) {
    if (!arcLifecycle.has(arcKey)) {
      arcLifecycle.set(arcKey, { birth: now, phase: 'new' });
    } else {
      const lc = arcLifecycle.get(arcKey);
      if (lc.phase === 'dying') {
        arcLifecycle.set(arcKey, { birth: now, phase: 'new' });
      }
    }
  }
  for (const arcKey of arcLifecycle.keys()) {
    if (!currentArcKeys.has(arcKey)) {
      const lc = arcLifecycle.get(arcKey);
      if (lc.phase !== 'dying') {
        arcLifecycle.set(arcKey, { ...lc, phase: 'dying', deathStarted: now });
      }
    }
  }

  // --- Include dying pins/arcs in the render payload until their animation completes. ---
  // Pins that are dying but no longer in currentPinKeys still need to appear
  // so the glitch-fade can play. Bandwidth cache is pruned *after* this loop
  // (in the cleanup block below) so `last` is guaranteed non-null here.
  for (const [pinKey, lc] of pinLifecycle) {
    if (lc.phase === 'dying' && !currentPinKeys.has(pinKey)) {
      const last = pinBandwidth.get(pinKey);
      if (last) {
        const labelRaw = last.country || '—';
        points.push({
          kind: 'dest',
          pinKey,
          pinLabel: escapeHtml(labelRaw),
          lat: last.lat,
          lng: last.lng,
          radius: 0.35,
          color: '#ff2bd6',
          pids: new Set(),
          label: `${escapeHtml(labelRaw)} (closing)`,
          countryRaw: labelRaw,
        });
      }
    }
  }
  for (const [arcKey, lc] of arcLifecycle) {
    if (lc.phase === 'dying' && !currentArcKeys.has(arcKey)) {
      // Dying arcs already sent to the scene remain; we just keep them alive
      // in arcsData by not re-adding them. globe.gl drops them on next setter.
      // To keep them visible during DYING_DURATION_MS we would need to
      // retain their geometry; since we can't reconstruct lat/lng here cheaply,
      // we accept a single-frame dropout for arcs and rely on the pin glitch
      // to carry the closing visual.
    }
  }

  // --- Clean up lifecycles once animations complete. ---
  for (const [pinKey, lc] of pinLifecycle) {
    if (lc.phase === 'new' && now - lc.birth > FLASH_DURATION_MS) {
      pinLifecycle.set(pinKey, { ...lc, phase: 'live' });
    }
    if (lc.phase === 'dying' && now - lc.deathStarted > DYING_DURATION_MS) {
      pinLifecycle.delete(pinKey);
      pinBandwidth.delete(pinKey); // keep bandwidth cache in lockstep
    }
  }
  for (const [arcKey, lc] of arcLifecycle) {
    if (lc.phase === 'new' && now - lc.birth > FLASH_DURATION_MS) {
      arcLifecycle.set(arcKey, { ...lc, phase: 'live' });
    }
    if (lc.phase === 'dying' && now - lc.deathStarted > DYING_DURATION_MS) {
      arcLifecycle.delete(arcKey);
    }
  }

  // Fingerprint — include presence of dying items so their removal triggers a redraw.
  const fingerprint = points.map(p => `${p.lat.toFixed(2)},${p.lng.toFixed(2)},${p.color},${p.kind}`).sort().join('|')
    + '#' + arcs.map(a => `${a.arcKey}`).sort().join('|')
    + '#L:' + [...pinLifecycle].map(([k, v]) => `${k}:${v.phase}`).sort().join(',');
  if (fingerprint === lastGlobeFingerprint) return;

  if (globeInteracting) {
    pendingGlobePayload = { points, arcs, fingerprint };
    return;
  }

  // Scene actually changed — now it's safe to re-bind the color fn and
  // swap geometry. Doing these unconditionally on every poll tick caused
  // globe.gl (with pointsMerge(false)) to stutter mid-drag.
  myGlobe.pointColor(pointColorFn);
  lastGlobeFingerprint = fingerprint;
  myGlobe.pointsData(points).arcsData(arcs);
}

// --- Animation loop: atmosphere pulse + per-frame color recomputes for lifecycles ---

// A pin that hasn't been seen in this many ms gets flipped to 'dying' by the
// animation loop — even if the next poll is still minutes away.
const PIN_STALE_MS = 3000;

function hasActiveLifecycle() {
  // No allocations — early-exit iteration.
  for (const lc of pinLifecycle.values()) {
    if (lc.phase === 'new' || lc.phase === 'dying') return true;
  }
  for (const lc of arcLifecycle.values()) {
    if (lc.phase === 'new' || lc.phase === 'dying') return true;
  }
  return false;
}

function startGlobeAnimationLoop() {
  let last = 0;
  let rafId = 0;
  const interval = 1000 / ANIM_FPS;

  function loop(t) {
    rafId = requestAnimationFrame(loop);
    if (t - last < interval) return;
    last = t;
    if (!myGlobe) return;
    // CRITICAL: do nothing while the user is dragging/zooming. Any globe.gl
    // setter call mid-gesture interrupts the orbit controller and the globe
    // appears to "stick" on every refresh.
    if (globeInteracting) return;

    // --- Staleness-driven lifecycle transition (decoupled from poll cadence) ---
    let transitioned = false;
    const now = performance.now();
    for (const [pinKey, lc] of pinLifecycle) {
      if (lc.phase !== 'dying' && lc.lastSeen !== undefined &&
          now - lc.lastSeen > PIN_STALE_MS) {
        pinLifecycle.set(pinKey, { ...lc, phase: 'dying', deathStarted: now });
        transitioned = true;
      }
      if (lc.phase === 'dying' && lc.deathStarted !== undefined &&
          now - lc.deathStarted > DYING_DURATION_MS) {
        pinLifecycle.delete(pinKey);
        pinBandwidth.delete(pinKey);
        transitioned = true;
      }
      if (lc.phase === 'new' && now - lc.birth > FLASH_DURATION_MS) {
        pinLifecycle.set(pinKey, { ...lc, phase: 'live' });
      }
    }
    if (transitioned) {
      updateGlobe(lastFilteredProcesses);
      renderTopTalkers();
    }

    // --- Atmosphere: stable light-blue neon. Altitude pulses with traffic;
    //     hue stays locked to cyan (no more shifting to green). ---
    let totalBytes = 0;
    for (const v of pinBandwidth.values()) totalBytes += v.bytes;
    const traffic = Math.min(1, Math.log10(1 + totalBytes) / 8);
    const basePulse = 0.5 + 0.5 * Math.sin(t / (1400 - 400 * traffic));
    const altitude = 0.14 + 0.04 * basePulse + 0.03 * traffic;
    // hsl(195, 90%, 65%) ≈ #57d8ff — neon cyan.
    const lightness = 62 + 4 * basePulse + 4 * traffic;
    myGlobe.atmosphereAltitude(altitude)
      .atmosphereColor(`hsl(195, 95%, ${lightness.toFixed(1)}%)`);

    // --- Recompute colors so lifecycle flashes/dissolves animate smoothly ---
    if (hasActiveLifecycle()) {
      myGlobe.pointColor(pointColorFn);
      myGlobe.arcColor(d => arcColorFn(d));
    }
  }

  function start() {
    if (rafId) return;
    last = 0;
    rafId = requestAnimationFrame(loop);
  }
  function stop() {
    if (rafId) cancelAnimationFrame(rafId);
    rafId = 0;
  }

  // Pause the loop entirely when the tab is backgrounded. Browsers throttle
  // rAF anyway, but this also stops the 2s setInterval-ish setter churn on
  // re-focus (setters still run via updateGlobe on poll ticks, not here).
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stop(); else start();
  });

  start();
}

// --- Top Talkers panel ---

function renderTopTalkers() {
  const listEl = document.getElementById('talkersList');
  if (!listEl) return;

  const entries = [...pinBandwidth.entries()]
    .map(([pinKey, v]) => ({ pinKey, ...v }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 3);

  if (entries.length === 0) {
    listEl.innerHTML = '<div class="talkers-empty">–– no traffic ––</div>';
    return;
  }

  const now = performance.now();
  listEl.innerHTML = entries.map((e, i) => {
    const recentBump = now - e.lastBump < 1200;
    return `<div class="talker-row ${recentBump ? 'talker-bump' : ''}">
      <span class="talker-rank">${i + 1}</span>
      <span class="talker-loc">${escapeHtml(e.country || '—')}</span>
      <span class="talker-bytes">${escapeHtml(formatBytes(e.bytes))}</span>
      <span class="talker-spark ${recentBump ? 'active' : ''}"></span>
    </div>`;
  }).join('');
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

// --- Hover a process card → highlight its arcs on the globe ---

appEl.addEventListener('mouseover', (e) => {
  const card = e.target.closest('.process-card');
  if (!card) return;
  const pid = parseInt(card.dataset.pid, 10);
  if (pid === hoveredPid) return;
  hoveredPid = pid;
  card.classList.add('process-hovered');
  if (myGlobe) {
    myGlobe.pointColor(pointColorFn);
    myGlobe.arcColor(d => arcColorFn(d));
  }
});

appEl.addEventListener('mouseout', (e) => {
  const card = e.target.closest('.process-card');
  if (!card) return;
  // Only clear if we're leaving the card entirely (not moving to a child).
  const related = e.relatedTarget;
  if (related && card.contains(related)) return;
  hoveredPid = null;
  card.classList.remove('process-hovered');
  if (myGlobe) {
    myGlobe.pointColor(pointColorFn);
    myGlobe.arcColor(d => arcColorFn(d));
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
[filterIPv6, filterPrivate, filterSystem].forEach(el => {
  el.addEventListener('change', () => { if (lastData) render(lastData); });
});

sortSelect.addEventListener('change', () => { if (lastData) render(lastData); });
expandAllBtn.addEventListener('click', () => expandAll());
collapseAllBtn.addEventListener('click', () => collapseAll());

let searchTimeout;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    // Manual search edits clear the pin focus state so the two stay consistent.
    if (focusedPinLabel && !searchInput.value.includes(focusedPinLabel)) {
      focusedPinLabel = null;
    }
    if (lastData) render(lastData);
  }, 200);
});

// --- Refresh orchestration ---

async function refreshAll({ fresh } = { fresh: false }) {
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

// List toggle: the process-detail panel is collapsed by default (body has
// `globe-pinned` class). Pressing the toggle slides the panel in from the
// left; pressing again collapses it back. The globe canvas is re-sized after
// the CSS transition settles so it fills whatever width it was just given.
function setListVisible(show) {
  const currentlyHidden = document.body.classList.contains('globe-pinned');
  const nextHidden = show === undefined ? !currentlyHidden : !show;
  document.body.classList.toggle('globe-pinned', nextHidden);
  if (!myGlobe) return;
  const resize = () => {
    if (!myGlobe) return;
    myGlobe.width(globeContainer.clientWidth).height(globeContainer.clientHeight);
  };
  // Match to the .left-panel CSS transition (260ms): fire once early to
  // catch the transition start and again at the end for the final width.
  requestAnimationFrame(resize);
  setTimeout(resize, 140);
  setTimeout(resize, 300);
}

listToggleBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  setListVisible();
});

document.addEventListener('keydown', (e) => {
  // Esc collapses the list panel back (only if currently open).
  if (e.key === 'Escape' && !document.body.classList.contains('globe-pinned')) {
    setListVisible(false);
  }
});

function flickerCounter(el) {
  el.classList.remove('counter-flicker');
  void el.offsetWidth;
  el.classList.add('counter-flicker');
}

// --- Init ---
initGlobe();
refreshAll({ fresh: true });
scheduleRefresh();
