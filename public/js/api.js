/* ============================================================
   NetWatcher — API fetch helpers
   All /api/* requests live here; render calls are replaced
   with bus emits so this module has zero dependency on render fns.
   ============================================================ */

import { S, emit, CSRF_HEADER } from './state.js';
import { el } from './dom.js';
import { escapeHtml, flag } from './util.js';

const {
  statusText, queueEl,
  hostHostname, hostLocalIP, hostPublicIP, hostLocation, hostISP,
  queueISP, queueGeo,
  blockedCountEl, blockedCntBig, footBlocked,
} = el;

// All /api/* requests must carry the CSRF header — the server enforces it
// on GETs too (except SSE). Using a non-simple header forces a CORS
// preflight on cross-origin attempts, which the Origin allowlist rejects.
// EventSource (traffic-stream) cannot use this — it relies on Host/Origin
// allowlist only.
export function apiFetch(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: { ...CSRF_HEADER, ...(options.headers || {}) },
  });
}

// ---------- API: host info ----------
export async function fetchHostInfo({ fresh } = { fresh: false }) {
  try {
    const res = await apiFetch('/api/host-info' + (fresh ? '?fresh=1' : ''));
    if (!res.ok) return;
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
    }
  } catch { /* silent */ }
}

// ---------- API: connections ----------
export async function fetchConnections() {
  const liveTraffic = S.liveTraffic;
  try {
    const res = await apiFetch('/api/connections');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    S.lastData = data;
    // Prune liveTraffic to the currently-live connections so the Map can't grow
    // unbounded as ephemeral sockets (TIME_WAIT, short UDP, browser conns) churn.
    const liveKeys = new Set();
    for (const p of data) for (const c of p.connections) liveKeys.add(c.trafficKey);
    for (const k of liveTraffic.keys()) if (!liveKeys.has(k)) liveTraffic.delete(k);
    statusText.textContent = S.streamHealthy ? 'streaming · live' : 'poll · stream offline';
    statusText.classList.toggle('err', !S.streamHealthy);
    statusText.classList.remove('wait');
    queueEl.querySelector('.queue-error-banner')?.remove(); // recovered — drop any stale-refresh banner
    emit('data:changed');
  } catch (err) {
    statusText.textContent = 'error';
    statusText.classList.add('err');
    // Surface the failure near the queue (the masthead status is far away).
    if (!S.lastData) {
      // Nothing rendered yet — show the full inline error + Retry.
      queueEl.innerHTML = `
        <div class="queue-empty queue-error">
          <div>Couldn't load connections — ${escapeHtml(err.message)}</div>
          <div><button class="queue-clear-filters" data-action="retry-connections">Retry</button></div>
        </div>`;
    } else if (!queueEl.querySelector('.queue-error-banner')) {
      // Keep the (stale) list but flag that it stopped refreshing, with a Retry,
      // so a sustained outage after the first successful load isn't invisible.
      // Built with DOM APIs + textContent (no innerHTML sink).
      const banner = document.createElement('div');
      banner.className = 'queue-error-banner';
      banner.textContent = `⚠ Couldn't refresh — ${err.message} `;
      const retry = document.createElement('button');
      retry.className = 'queue-clear-filters';
      retry.dataset.action = 'retry-connections';
      retry.textContent = 'Retry';
      banner.appendChild(retry);
      queueEl.insertBefore(banner, queueEl.firstChild);
    }
  }
}

// ---------- API: blocked ----------
export async function fetchBlockedIPs() {
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
    S.blockedMeta = new Map();
    for (const rec of (data.active || [])) {
      S.blockedMeta.set(rec.ip, {
        country: rec.country,
        countryCode: rec.countryCode || null,
        isp: rec.isp || null,
        blockedAt: rec.blockedAt,
      });
    }
    S.blocksStale = !!data.stale;
    S.staleCount = data.staleCount || 0;
  } catch { /* silent */ }
  // Display source = the persisted active list (stable: it survives the common
  // case where pfctl is unreadable because the sudo timestamp lapsed ~5 min
  // after the last action), unioned with live pfctl when it IS readable so a
  // block made outside the app still shows.
  S.blockedIPs = new Set(livePfctl ?? []);
  for (const ip of S.blockedMeta.keys()) S.blockedIPs.add(ip);
  emit('blocked:changed');
  if (blockedCountEl) blockedCountEl.textContent = S.blockedIPs.size;
  blockedCntBig.textContent = S.blockedIPs.size;
  footBlocked.textContent = S.blockedIPs.size;
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
