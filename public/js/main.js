/* ============================================================
   NetWatcher — wiring real API to the Radar Room redesign
   ============================================================ */

import { formatBytes } from './util.js';
import { el } from './dom.js';
import { S } from './state.js';
import { fetchConnections, fetchHostInfo, fetchBlockedIPs } from './api.js';
import { initRadar } from './radar.js';
import { pushThroughput, initPanels } from './panels.js';
import { initBlockedPanel } from './modals.js';
import { initActions } from './actions.js';
import { initConnectionList } from './connection-list.js';

// ---------- DOM ----------
const {
  statusText, refreshSelect, refreshNowBtn,
  qEl,
  footRefresh,
} = el;

// ---------- Keyboard
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
      const prevBytes = S.liveTraffic.get(e.key);
      if (prevBytes) {
        // A *decreasing* counter means nettop reset / the 5-tuple was reused:
        // count the fresh absolute value rather than dropping the delta to 0.
        const drx = bytesIn < prevBytes.bytesIn ? bytesIn : bytesIn - prevBytes.bytesIn;
        const dtx = bytesOut < prevBytes.bytesOut ? bytesOut : bytesOut - prevBytes.bytesOut;
        rxBytesPerSec += Math.max(0, drx);
        txBytesPerSec += Math.max(0, dtx);
      }
      S.liveTraffic.set(e.key, { bytesIn, bytesOut });
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

// ---------- Bus subscriptions ----------
// blocked:changed is now owned by modals.js (registered inside initBlockedPanel())
// host:changed is now owned by radar.js (registered inside initRadar())
// data:changed is now owned by connection-list.js (registered inside initConnectionList())

// ---------- Init ----------
statusText.classList.add('wait');
statusText.textContent = 'connecting…';
initRadar();
initPanels();
initBlockedPanel();
initActions();
initConnectionList();
connectTrafficStream();
refreshAll({ fresh: true });
scheduleRefresh();
