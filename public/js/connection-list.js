/* ============================================================
   NetWatcher — Connection queue: render, filters, events
   ============================================================ */

import { escapeHtml, isIPv6, isPrivateIP, isLocalhost, flag, formatBytes, describeBlock, summarizeProcesses, canonicalIP } from './util.js';
import { el, preserveFocus } from './dom.js';
import { S, on, emit } from './state.js';
import { fetchConnections } from './api.js';
import { showToast } from './modals.js';
import { prefersReducedMotion, updateRadar } from './radar.js';
import { killProcessAction, vtCheckAction, blockIPAction, unblockIPAction } from './actions.js';
import { filterMapProcesses, processKey } from './radar-data.js';
import { renderVerificationBadge, renderVerificationDetails } from './process-verification.js';

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

function blockState(ip) {
  return describeBlock(ip, S.pfIPs, S.blockedMeta, S.staleCount, S.historyFresh, S.firewallStatus);
}
function processRate(proc, direction) {
  if (!S.streamHealthy || Date.now() - S.lastDeltaAt > 3000) return 0;
  return proc.connections.reduce((sum, c) => sum + (liveTraffic.get(c.trafficKey)?.[direction + 'Bps'] || 0), 0);
}
function processRateLabel(proc) {
  if (S.paused) return 'Paused';
  if (!S.streamHealthy || !S.hasRateSample || !S.lastDeltaAt || Date.now() - S.lastDeltaAt > 3000) return 'Rate unavailable';
  return `↓${formatBytes(processRate(proc, 'rx'))}/s ↑${formatBytes(processRate(proc, 'tx'))}/s`;
}
function updateTrafficSummaries() {
  if (!S.lastData) return;
  if (S.paused) {
    updateRadar(applyFilters(S.lastData, false));
    queueEl.querySelectorAll('[data-role="proc-rate"]').forEach(el => { el.textContent = 'Paused'; });
    return;
  }
  const filtered = applyFilters(S.lastData);
  const speedSort = ['rx', 'tx'].includes(sortSelect.value);
  if (speedSort && !queueEl.contains(document.activeElement) && !document.querySelector('dialog[open]')) renderQueue(true);
  for (const proc of filtered) {
    const row = queueEl.querySelector(`.row[data-pid="${proc.pid}"]`);
    const total = row?.querySelector('[data-role="proc-total"]');
    const rate = row?.querySelector('[data-role="proc-rate"]');
    if (total) total.textContent = `Total ↓↑ ${formatBytes(procSummary(proc).totalBytes)}`;
    if (rate) rate.textContent = processRateLabel(proc);
  }
  renderTopTalkers(filtered);
  updateRadar(applyFilters(S.lastData, false));
}

// ---------- Sort / filter ----------
function sortProcesses(processes) {
  const mode = sortSelect.value;
  return [...processes].sort((a, b) => {
    if (mode === 'pid') return a.pid - b.pid;
    if (mode === 'name') return a.processName.localeCompare(b.processName);
    if (mode === 'rx' || mode === 'tx') return processRate(b, mode) - processRate(a, mode) || a.pid - b.pid;
    return b.connections.length - a.connections.length;
  });
}

function applyFilters(processes, withMap = true) {
  const search = filter.q.toLowerCase().trim();
  const base = processes
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
  return withMap ? filterMapProcesses(base, S.mapSelection) : base;
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
  const filt = `${filter.sys ? 1 : 0}${filter.v6 ? 1 : 0}${filter.priv ? 1 : 0}|${filter.q}|${JSON.stringify(S.mapSelection)}`;
  const blocks = [...S.blockedIPs].sort().map(ip => [ip, blockState(ip).label]);
  return JSON.stringify([sort, exp, filt, blocks, S.connectionsError, S.lastData.map(p => ({
    ...p, connections: p.connections.map(({ bytesIn, bytesOut, ...c }) => c),
  }))]);
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
  btn.setAttribute('aria-label', btn.title);
  btn.setAttribute('aria-expanded', String(allOpen));
}

function renderQueueEmpty() {
  const anyFilterOn = filter.sys || filter.v6 || filter.priv || filter.q || S.mapSelection;
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
    : proc.connections.every(c => isPrivateIP(c.remoteAddress)) ? 'Local network' : 'Location unknown';
  const traffic = `Total ↓↑ ${formatBytes(summary.totalBytes)}`;
  const killBtn = `<button ${!proc.identity?.token ? 'disabled' : ''} class="kill ${proc.isSystemProcess ? 'danger' : ''}" data-action="kill" data-pid="${proc.pid}" data-name="${escapeHtml(proc.processName)}" data-system="${proc.isSystemProcess ? '1' : '0'}" data-focus-key="kill-${proc.pid}" aria-label="End ${escapeHtml(proc.processName)} (PID ${proc.pid})" title="End PID ${proc.pid}">End process</button>`;

  const rowHtml = `
    <div class="row ${proc.isSystemProcess ? 'sys' : ''} ${expanded ? 'active' : ''}" data-pid="${proc.pid}">
      <div class="idx">${idx}</div>
      <div class="name"><button class="process-toggle" data-action="toggle" data-pid="${proc.pid}" data-focus-key="toggle-${proc.pid}" aria-expanded="${expanded}" aria-controls="connections-${proc.pid}"><span aria-hidden="true">${expanded ? "▾" : "▸"}</span><span class="pname" title="${escapeHtml(proc.description || proc.processName)}">${escapeHtml(proc.processName)}</span></button>${killBtn}</div>
      <div class="n">
        <span>${proc.connections.length}</span>
        <span class="bar"><span style="transform:scaleX(${w})"></span></span>
      </div>
      <div class="meta">
        <span>pid ${proc.pid}</span>${proc.isSystemProcess ? '<span title="Classification based on the process name">System label</span>' : ''}
        ${renderVerificationBadge(proc.verification)}
        <span class="sep">·</span>
        <span>${countryLabel}</span>
        <span class="sep">·</span><span data-role="proc-total">${traffic}</span><span data-role="proc-rate">${processRateLabel(proc)}</span>
      </div>
    </div>
  `;

  if (!expanded) return rowHtml;
  const identity = proc.identity;
  const details = identity
    ? `<div class="identity-note">OS-reported path: <code>${escapeHtml(identity.executable)}</code><br>UID ${identity.uid} · Parent PID ${identity.parentPid} · Started ${escapeHtml(identity.startedAt)}${renderVerificationDetails(proc.verification)}</div>`
    : '<div class="identity-note">Process identity unavailable. Ending this process is disabled until identity can be read.</div>';
  return rowHtml + details + renderConnBlock(proc);
}

function renderConnBlock(proc) {
  const rows = proc.connections.map((conn, index) => {
    const geo = conn.geo;
    const f = flag(geo?.countryCode);
    const countryLabel = geo
      ? `${f}${geo.city ? ' ' + escapeHtml(geo.city) + ', ' : ' '}${escapeHtml(geo.country || '')}`
      : isPrivateIP(conn.remoteAddress) ? 'Local network'
      : conn.enrichment?.geo === 'pending' ? 'Looking up location…'
      : conn.enrichment?.geo === 'rate-limited' ? 'Location service rate limited' : 'Location unavailable';
    const ispLabel = geo?.isp ? `<span class="isp" title="${escapeHtml(geo.isp)}">${escapeHtml(geo.isp)}</span>` : '';
    const dom = conn.domain && conn.domain !== '-'
      ? `<span class="dom" title="Reverse DNS name; not a verified application destination">PTR: ${escapeHtml(conn.domain)}</span>`
      : conn.enrichment?.dns === 'pending' ? '<span class="dom">Looking up PTR…</span>' : '';
    const tKey = conn.trafficKey;
    const live = liveTraffic.get(tKey);
    const rx = live ? live.bytesIn : conn.bytesIn;
    const tx = live ? live.bytesOut : conn.bytesOut;
    const canFirewall = !isPrivateIP(conn.remoteAddress) && !isLocalhost(conn.remoteAddress);
    const blocked = S.blockedIPs.has(canonicalIP(conn.remoteAddress));
    const focusKey = `${proc.pid}-${conn.trafficKey}-${index}`;
    const acts = [`<button data-action="copy" data-copy="${escapeHtml(conn.remoteAddress)}" data-focus-key="copy-${escapeHtml(focusKey)}">Copy IP</button>`];
    if (conn.domain && conn.domain !== '-') acts.push(`<button data-action="copy" data-copy="${escapeHtml(conn.domain)}" data-focus-key="domain-${escapeHtml(focusKey)}">Copy domain</button>`);
    if (canFirewall) {
      acts.push(`<button class="vt" data-focus-key="vt-${escapeHtml(focusKey)}" data-action="vt" data-ip="${escapeHtml(conn.remoteAddress)}" title="VirusTotal lookup">VirusTotal</button>`);
      if (blocked) {
        acts.push(`<button class="unblock" data-focus-key="unblock-${escapeHtml(focusKey)}" data-action="unblock" data-ip="${escapeHtml(conn.remoteAddress)}" title="Remove from pf block table">Unblock</button>`);
      } else {
        acts.push(`<button class="block" data-focus-key="block-${escapeHtml(focusKey)}" data-action="block" data-ip="${escapeHtml(conn.remoteAddress)}" title="Add to pf block table">Block</button>`);
      }
    }
    const state = blockState(conn.remoteAddress);
    const blockedTag = blocked ? `<span class="blocked-tag ${state.kind}">${state.label}</span>` : '';
    return `
      <div class="c" data-ip="${escapeHtml(conn.remoteAddress)}" data-traffic-key="${escapeHtml(tKey)}">
        <span class="ip"><span class="proto">${escapeHtml(conn.protocol || '')}</span><b>${escapeHtml(conn.remoteAddress)}</b><span class="port">:${conn.remotePort}</span>${dom}</span>
        <span class="meta">
          <span>${countryLabel}</span>
          ${ispLabel}
          <span class="rx" data-role="rx" title="Cumulative received bytes">↓${formatBytes(rx)}</span>
          <span class="tx" data-role="tx" title="Cumulative sent bytes">↑${formatBytes(tx)}</span>
          ${blockedTag}
        </span>
        <span class="acts">${acts.join('')}</span>
      </div>
    `;
  }).join('');
  return `<div class="conn" id="connections-${proc.pid}">${rows}</div>`;
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
    talkersListEl.innerHTML = `<div class="line"><span class="k">${sorted.some(p => p.connections.length) ? 'Geolocation unavailable for these connections' : 'No connections in current view'}</span></div>`;
    return;
  }
  talkersListEl.innerHTML = entries.map(([country, bytes]) =>
    `<div class="line"><span class="k">${escapeHtml(country)}</span><span class="v">${escapeHtml(formatBytes(bytes))}</span></div>`,
  ).join('');
}

function renderQueue(force = false) {
  if (document.querySelector('dialog[open]')) return;
  if (!S.lastData) {
    queueEl.innerHTML = `<div class="queue-empty">${S.connectionsError ? 'Connections unavailable. Use Retry above.' : 'Loading connections…'}</div>`;
    dProc.textContent = dProcSys.textContent = dProcUsr.textContent = dConn.textContent = dCtry.textContent = '—';
    dConnSub.textContent = dCtrySub.textContent = 'No connection snapshot';
    el.queueSummary.textContent = S.connectionsError ? 'Connection snapshot unavailable' : 'Loading connection snapshot…';
    talkersListEl.textContent = 'No connection snapshot';
    S.lastRenderSig = '';
    updateRadar([]);
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
  const restoreFocus = preserveFocus(queueEl);

  if (sorted.length === 0) {
    queueEl.innerHTML = renderQueueEmpty();
  } else {
    queueEl.innerHTML = sorted.map((p, i) => renderProcRow(p, i)).join('');
    flashNewRows(sorted);
  }
  restoreFocus();
  S.prevPids = new Set((S.lastData || []).map((p) => p.pid));
  S.prevConnKeys = new Set((S.lastData || []).flatMap((p) => p.connections.map((c) => `${p.pid}|${c.remoteAddress}`)));

  const totals = summarizeProcesses(sorted);
  dProc.textContent = totals.processes;
  dProcSys.textContent = totals.system;
  dProcUsr.textContent = totals.user;
  dConn.textContent = totals.connections;
  dConnSub.textContent = `${totals.established} EST · ${totals.timewait} TIME_WAIT · ${totals.other} other`;
  dCtry.textContent = totals.countries;
  dCtrySub.textContent = `${totals.providers} service provider${totals.providers === 1 ? '' : 's'}`;
  el.queueSummary.textContent = `Showing ${sorted.length} of ${S.lastData.length} processes · your user’s connections`;

  updateChipCounts(filtered.length);
  renderTopTalkers(sorted);
  updateRadar(applyFilters(S.lastData, false));
}

function clearFilters() {
  filter.sys = false;
  filter.v6 = false;
  filter.priv = false;
  filter.q = '';
  S.mapSelection = null;
  S.mapProcess = null;
  for (const key of ['sys', 'v6', 'priv']) {
    const chip = chipsEl.querySelector(`.chip[data-f="${key}"]`);
    chip?.classList.remove('on');
    chip?.setAttribute('aria-pressed', 'false');
  }
  qEl.value = '';
  renderQueue();
}

// ---------- Export: wire all queue/search/sort/chips/qToggle listeners ----------
export function initConnectionList() {
  // Bus: drive renderQueue from data:changed (replaces shim in main.js)
  on('data:changed', () => renderQueue());
  on('map:selection', () => renderQueue(true));
  on('map:inspect', () => {
    const visible = applyFilters(S.lastData || []);
    for (const proc of visible) expandedPids.add(proc.pid);
    document.body.classList.remove('queue-collapsed');
    qToggleBtn.setAttribute('aria-expanded', 'true');
    qToggleBtn.title = 'Collapse process list';
    qToggleBtn.setAttribute('aria-label', qToggleBtn.title);
    qToggleIcon.setAttribute('d', 'M10 4 L5 8 L10 12');
    renderQueue(true);
    const first = queueEl.querySelector('.process-toggle');
    first?.focus({ preventScroll: true });
    first?.scrollIntoView({ block: 'nearest', behavior: 'instant' });
  });
  on('dialog:closed', () => renderQueue());
  on('traffic:changed', updateTrafficSummaries);
  on('stream:changed', () => { if (S.paused || !S.streamHealthy) updateTrafficSummaries(); });
  setInterval(() => { if (!document.hidden) updateTrafficSummaries(); }, 2000);

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
      const proc = S.lastData?.find(p => p.pid === pid);
      S.mapProcess = proc && expandedPids.has(pid) ? processKey(proc) : null;
      emit('map:process');
      renderQueue();
      return;
    }
    if (action === 'clear-filters') { clearFilters(); return; }
    if (action === 'retry-connections') { fetchConnections({ force: true }); return; }
    if (action === 'copy') {
      Promise.resolve().then(() => navigator.clipboard.writeText(target.dataset.copy)).then(() => showToast('Copied to clipboard', 'success'), () => showToast('Could not copy. Select the address and copy it manually.', 'error'));
      return;
    }
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
    b.setAttribute('aria-pressed', String(b.classList.contains('on')));
    if (f in filter) filter[f] = b.classList.contains('on');
    renderQueue();
  });

  // Queue collapse toggle
  qToggleBtn.addEventListener('click', () => {
    document.body.classList.toggle('queue-collapsed');
    const collapsed = document.body.classList.contains('queue-collapsed');
    qToggleBtn.title = collapsed ? 'Expand process list' : 'Collapse process list';
    qToggleBtn.setAttribute('aria-label', qToggleBtn.title);
    qToggleBtn.setAttribute('aria-expanded', String(!collapsed));
    qToggleIcon.setAttribute('d', collapsed ? 'M6 4 L11 8 L6 12' : 'M10 4 L5 8 L10 12');
    window.dispatchEvent(new Event('resize'));
  });
}
