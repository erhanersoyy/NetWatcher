import { showSessionRequired } from './session.js';
/* ============================================================
   NetWatcher — API fetch helpers
   All /api/* requests live here; render calls are replaced
   with bus emits so this module has zero dependency on render fns.
   ============================================================ */

import { S, emit, CSRF_HEADER } from './state.js';
import { el } from './dom.js';
import { escapeHtml, flag, canonicalIP } from './util.js';

const {
  listStatus, hostStatus, blockedStatus, footAnchor,
  hostHostname, hostLocalIP, hostPublicIP, hostLocation, hostISP,
  queueISP, queueGeo,
  blockedCountEl, blockedCntBig, footBlocked,
} = el;

// All /api/* requests must carry the CSRF header — the server enforces it
// on GETs too (except SSE). Using a non-simple header forces a CORS
// preflight on cross-origin attempts, which the Origin allowlist rejects.
// EventSource (traffic-stream) uses the session cookie plus Host/Origin checks.
export async function apiFetch(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { ...CSRF_HEADER, ...(options.headers || {}) },
  });
  if (response.status === 401) showSessionRequired();
  return response;
}

// ---------- API: host info ----------
let hostRequest = null, hostRetryTimer = null;
export function fetchHostInfo(options = { fresh: false }) {
  if (hostRequest) return hostRequest;
  clearTimeout(hostRetryTimer);
  hostRequest = loadHostInfo(options).finally(() => { hostRequest = null; });
  return hostRequest;
}
async function loadHostInfo({ fresh }) {
  try {
    const res = await apiFetch('/api/host-info' + (fresh ? '?fresh=1' : ''));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    S.hostInfo = await res.json();
    hostHostname.textContent = S.hostInfo.hostname || '—';
    hostLocalIP.textContent = S.hostInfo.localIP || '—';
    hostPublicIP.textContent = S.hostInfo.publicIP || '—';
    if (S.hostInfo.geo) {
      const f = flag(S.hostInfo.geo.countryCode);
      const locText = `${S.hostInfo.geo.city ? S.hostInfo.geo.city + ', ' : ''}${S.hostInfo.geo.country || ''}`;
      hostLocation.innerHTML = `${f} ${escapeHtml(S.hostInfo.geo.city ? S.hostInfo.geo.city + ', ' : '')}${escapeHtml(S.hostInfo.geo.country || '')}`;
      hostISP.textContent = S.hostInfo.geo.isp || '—';
      if (queueISP) queueISP.textContent = S.hostInfo.geo.isp || '—';
      if (queueGeo) queueGeo.innerHTML = `${f} ${escapeHtml(locText)}`;
      emit('host:changed', { lat: S.hostInfo.geo.lat, lon: S.hostInfo.geo.lon });
    } else {
      const label = S.hostInfo.geoStatus === 'pending' ? 'Looking up location…'
        : S.hostInfo.geoStatus === 'rate-limited' ? 'Location service rate limited' : 'Location unavailable';
      hostLocation.textContent = queueGeo.textContent = label;
      hostISP.textContent = queueISP.textContent = '—';
      emit('host:changed', { lat: null, lon: null });
    }
    hostStatus.textContent = S.hostInfo.publicIPStatus === 'unavailable' ? 'Public-IP lookup unavailable · retrying automatically'
      : S.hostInfo.geoStatus === 'pending' ? 'Public IP available · location lookup in progress'
      : S.hostInfo.geoStatus === 'rate-limited' ? 'Location service rate limited' + (S.hostInfo.geoRetryAt ? ` · retry after ${new Date(S.hostInfo.geoRetryAt).toLocaleTimeString()}` : '')
      : `Host information checked ${new Date().toLocaleTimeString()}`;
    if (S.hostInfo.geoStatus === 'pending') hostRetryTimer = setTimeout(() => {
      if (!document.hidden) fetchHostInfo();
    }, 2000);
  } catch {
    hostStatus.textContent = S.hostInfo ? 'Host information unavailable · showing last known values' : 'Host information unavailable';
  }
}

// ---------- API: connections ----------
let connectionsRequest = null;
export function fetchConnections({ force = false } = {}) {
  if (S.paused && !force) return Promise.resolve();
  if (connectionsRequest) return connectionsRequest;
  connectionsRequest = loadConnections(force).finally(() => { connectionsRequest = null; });
  return connectionsRequest;
}

async function loadConnections(force) {
  const version = S.monitorVersion;
  try {
    const res = await apiFetch('/api/connections');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error('Invalid connection data');
    if (version !== S.monitorVersion && !force) return;
    S.lastData = data;
    const liveKeys = new Set(data.flatMap(p => p.connections.map(c => c.trafficKey)));
    for (const key of S.liveTraffic.keys()) if (!liveKeys.has(key)) S.liveTraffic.delete(key);
    S.connectionsUpdatedAt = Date.now();
    S.connectionsError = '';
    document.getElementById('queueError').hidden = true;
    emit('data:changed');
  } catch (err) {
    if (version !== S.monitorVersion && !force) return;
    S.connectionsError = err.message;
    const banner = document.getElementById('queueError');
    banner.replaceChildren(document.createTextNode(`Couldn't refresh connections: ${err.message}. `));
    const retry = document.createElement('button');
    retry.className = 'queue-clear-filters';
    retry.textContent = 'Retry';
    retry.addEventListener('click', () => fetchConnections({ force: true }));
    banner.appendChild(retry);
    banner.hidden = false;
    emit('data:changed');
  } finally {
    updateListStatus();
  }
}

export function updateListStatus() {
  const checked = S.connectionsUpdatedAt
    ? `Last list update ${new Date(S.connectionsUpdatedAt).toLocaleTimeString()}`
    : 'No connection snapshot yet';
  listStatus.textContent = `${S.paused ? 'Paused · ' : ''}${checked}${S.connectionsError ? ' · refresh failed' : ''}`;
}

// ---------- API: blocked ----------
let blockedRequest = null;
export function fetchBlockedIPs() {
  if (blockedRequest) return blockedRequest;
  blockedRequest = loadBlockedIPs().finally(() => { blockedRequest = null; });
  return blockedRequest;
}

async function loadBlockedIPs() {
  let livePfctl = null;
  S.firewallStatus = null;
  try {
    const res = await apiFetch('/api/firewall-status');
    if (res.ok) {
      const status = await res.json();
      S.firewallStatus = status;
      if (Array.isArray(status.tableIPs)) livePfctl = new Set(status.tableIPs.map(canonicalIP));
    }
  } catch { /* Unreadable is unknown, never an empty table. */ }
  S.pfIPs = livePfctl;
  S.blocksCheckedAt = Date.now();
  S.historyFresh = false;
  S.historyError = '';
  try {
    const res = await apiFetch('/api/block-history');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data.active) || !Array.isArray(data.history)) throw new Error('Invalid history data');
    S.historyData = data;
    S.blockedMeta = new Map(data.active.map(rec => [canonicalIP(rec.ip), rec]));
    S.blocksStale = !!data.stale;
    S.staleCount = Number(data.staleCount) || 0;
    S.historyFresh = true;
  } catch (err) {
    S.historyError = `Saved rules could not be refreshed: ${err.message}`;
  }
  S.blockedIPs = new Set(livePfctl ?? []);
  for (const ip of S.blockedMeta.keys()) S.blockedIPs.add(ip);
  const time = new Date(S.blocksCheckedAt).toLocaleTimeString();
  const health = S.firewallStatus;
  const configChecked = health?.pfEnabled === true && health?.anchorLinked === true && health?.rulesPresent === true;
  const disabled = health?.pfEnabled === false;
  const incomplete = health?.anchorLinked === false || health?.rulesPresent === false;
  const summary = disabled ? 'PF is disabled' : incomplete ? 'Firewall rules missing or disconnected'
    : configChecked ? 'PF configuration checked' : 'PF configuration unverified';
  footAnchor.textContent = summary;
  footAnchor.className = !configChecked ? 'unverified' : '';
  blockedStatus.classList.toggle('unverified', !configChecked);
  blockedStatus.textContent = S.historyError || `${summary} · ${livePfctl === null ? 'table unavailable' : `table checked ${time}`}. Traffic blocking has not been independently tested.`;
  emit('blocked:changed');
  const count = livePfctl !== null || S.historyData !== null ? S.blockedIPs.size : '—';
  if (blockedCountEl) blockedCountEl.textContent = count;
  blockedCntBig.textContent = count;
  footBlocked.textContent = count;
  if (S.lastData) emit('data:changed');
}

// Re-apply all persisted blocks to pf in one request. `sendFirewallRequest`
// already POSTs { password } and zeroes it after send; the ip arg is unused
// by that helper (the path carries no ip here).
export function reapplyBlocks(password) {
  return sendFirewallRequest('/api/reapply', '', password);
}

// ---------- Firewall ----------
export async function sendFirewallRequest(path, ip, password) {
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
