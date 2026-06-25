/* ============================================================
   NetWatcher — wiring real API to the Radar Room redesign
   ============================================================ */

import { el } from './dom.js';
import { S } from './state.js';
import { fetchConnections, fetchHostInfo, fetchBlockedIPs } from './api.js';
import { initRadar } from './radar.js';
import { initPanels } from './panels.js';
import { initBlockedPanel } from './modals.js';
import { initActions } from './actions.js';
import { initConnectionList } from './connection-list.js';
import { connectTrafficStream } from './sse.js';

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
