/* ============================================================
   NetWatcher — Connection queue: render, filters, events
   ============================================================ */

import { escapeHtml, isIPv6, isPrivateIP, isLocalhost, flag, formatBytes } from './util.js';
import { el } from './dom.js';
import { S, on } from './state.js';
import { fetchConnections } from './api.js';
import { prefersReducedMotion } from './radar.js';
import { killProcessAction, vtCheckAction, blockIPAction, unblockIPAction } from './actions.js';

// ---------- DOM aliases ----------
const {
  queueEl, qEl, sortSelect, chipsEl,
  qToggleBtn, qToggleIcon,
  dProc, dProcSys, dProcUsr, dConn, dConnSub, dCtry, dCtrySub,
  talkersListEl, footSort,
} = el;

// ---------- State aliases ----------
const liveTraffic  = S.liveTraffic;   // Map — mutated in place only
const expandedPids = S.expandedPids;  // Set — mutated in place only
const filter       = S.filter;        // object — mutated in place only

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
  let primary = null, best = 0;
  for (const [cc, n] of countries) {
    if (n > best) { best = n; primary = cc; }
  }
  return { primaryCC: primary, totalBytes, countryCount: countries.size };
}

// ---------- Render sig / skip-guard ----------
function computeRenderSig() {
  if (!S.lastData) return '';
  const sort = sortSelect.value;
  const exp = [...expandedPids].sort((a, b) => a - b).join(',');
  const filt = `${filter.sys ? 1 : 0}${filter.v6 ? 1 : 0}${filter.priv ? 1 : 0}|${filter.q}`;
  const blocked = [...S.blockedIPs].sort().join(',');
  const dataParts = [];
  for (const p of S.lastData) {
    dataParts.push(`${p.pid}:${p.connections.length}`);
    for (const c of p.connections) {
      dataParts.push(`${c.remoteAddress}:${c.remotePort}:${c.state}`);
    }
  }
  return `${sort}|${exp}|${filt}|${blocked}|${dataParts.join(';')}`;
}

// ---------- Render ----------
function updateExpandToggle(visible) {
  const btn = document.getElementById('expandToggleChip');
  if (!btn || !S.lastData) return;
  if (!visible) visible = applyFilters(S.lastData);
  const allOpen = visible.length > 0 && visible.every((p) => expandedPids.has(p.pid));
  btn.classList.toggle('all-expanded', allOpen);
  const lbl = btn.querySelector('.lbl');
  if (lbl) lbl.textContent = allOpen ? 'collapse all' : 'expand all';
  btn.title = allOpen ? 'Collapse all' : 'Expand all';
}

function renderQueueEmpty() {
  const anyFilterOn = filter.sys || filter.v6 || filter.priv || filter.q;
  const clearBtn = anyFilterOn
    ? '<div><button class="queue-clear-filters" data-action="clear-filters">Clear filters</button></div>'
    : '';
  const msg = anyFilterOn ? 'No connections match current filters' : 'No connections';
  return `<div class="queue-empty">${msg}${clearBtn}</div>`;
}

function flashNewRows(sorted) {
  if (S.prevPids === null || prefersReducedMotion()) return;
  for (const p of sorted) {
    const isNewProcess = !S.prevPids.has(p.pid);
    const hasNewRemote = p.connections.some((c) => !S.prevConnKeys.has(`${p.pid}|${c.remoteAddress}`));
    if (!isNewProcess && !hasNewRemote) continue;
    const row = queueEl.querySelector(`.row[data-pid="${CSS.escape(String(p.pid))}"] .pname`);
    if (row) row.classList.add('flash');
  }
}

function hiddenCounts(baseCount) {
  if (!S.lastData) return { sys: 0, v6: 0, priv: 0 };
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

function renderTopTalkers(sorted) {
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
  S.prevPids = new Set((S.lastData || []).map((p) => p.pid));
  S.prevConnKeys = new Set((S.lastData || []).flatMap((p) => p.connections.map((c) => `${p.pid}|${c.remoteAddress}`)));

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

  updateChipCounts(filtered.length);
  renderTopTalkers(sorted);
}

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

// ---------- Export: wire all queue/search/sort/chips/qToggle listeners ----------
export function initConnectionList() {
  // Bus: drive renderQueue from data:changed (replaces shim in main.js)
  on('data:changed', () => renderQueue());

  // Queue click delegation: toggle, clear-filters, retry, kill, vt, block, unblock
  queueEl.addEventListener('click', (e) => {
    const target = e.target.closest('[data-action]');
    if (!target) return;
    const action = target.dataset.action;
    if (action === 'toggle') {
      if (e.target.closest('.conn')) return;
      const pid = Number(target.dataset.pid);
      if (expandedPids.has(pid)) expandedPids.delete(pid);
      else expandedPids.add(pid);
      renderQueue();
      return;
    }
    if (action === 'clear-filters') { clearFilters(); return; }
    if (action === 'retry-connections') { fetchConnections(); return; }
    e.stopPropagation();
    if (action === 'kill') {
      killProcessAction(Number(target.dataset.pid), target.dataset.name, target.dataset.system === '1', target);
    } else if (action === 'vt') {
      vtCheckAction(target.dataset.ip, target);
    } else if (action === 'block') {
      blockIPAction(target.dataset.ip, target);
    } else if (action === 'unblock') {
      unblockIPAction(target.dataset.ip, target);
    }
  });

  // Keyboard: Enter/Space toggle + focus restore
  queueEl.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const row = e.target.closest?.('.row[data-action="toggle"]');
    if (!row) return;
    e.preventDefault();
    const pid = row.dataset.pid;
    row.click();
    queueEl.querySelector(`.row[data-pid="${CSS.escape(pid)}"]`)?.focus();
  });

  // Search (debounced)
  let searchTimer;
  qEl.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      filter.q = qEl.value;
      renderQueue();
    }, 150);
  });

  // Sort select
  sortSelect.addEventListener('change', () => {
    footSort.textContent = sortSelect.value;
    renderQueue();
  });

  // Chips: filter toggles + expand-all
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

  // Queue collapse toggle
  qToggleBtn.addEventListener('click', () => {
    document.body.classList.toggle('queue-collapsed');
    const collapsed = document.body.classList.contains('queue-collapsed');
    qToggleBtn.title = collapsed ? 'Expand process list' : 'Collapse process list';
    qToggleIcon.setAttribute('d', collapsed ? 'M6 4 L11 8 L6 12' : 'M10 4 L5 8 L10 12');
    window.dispatchEvent(new Event('resize'));
  });
}
