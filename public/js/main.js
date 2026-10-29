import { establishSession, showSessionRequired } from './session.js';
import { el } from './dom.js';
import { S, emit } from './state.js';
import { fetchConnections, fetchHostInfo, fetchBlockedIPs, updateListStatus } from './api.js';
import { initRadar } from './radar.js';
import { initPanels } from './panels.js';
import { initBlockedPanel } from './modals.js';
import { initActions } from './actions.js';
import { initConnectionList } from './connection-list.js';
import { connectTrafficStream, disconnectTrafficStream } from './sse.js';

if (await establishSession()) {

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey || document.querySelector('dialog[open]')) return;
  if (document.activeElement?.matches('input, textarea, select, [contenteditable="true"]')) return;
  if (e.key === '/') { e.preventDefault(); el.qEl.focus(); }
});

let refreshing = false;
async function refreshAll({ fresh = false, force = false } = {}) {
  if (refreshing) return;
  refreshing = true;
  el.refreshNowBtn.disabled = true;
  el.refreshNowBtn.classList.add('spinning');
  try {
    await Promise.all([fetchConnections({ force }), fetchHostInfo({ fresh }), fetchBlockedIPs()]);
  } finally {
    refreshing = false;
    el.refreshNowBtn.disabled = false;
    el.refreshNowBtn.classList.remove('spinning');
  }
}
function scheduleRefresh() {
  clearInterval(S.refreshTimer);
  S.refreshTimer = setInterval(() => {
    if (!S.paused && !document.hidden) fetchConnections();
  }, S.refreshIntervalMs);
}
el.refreshSelect.addEventListener('change', () => {
  S.refreshIntervalMs = Number(el.refreshSelect.value);
  el.footRefresh.textContent = el.refreshSelect.selectedOptions[0].textContent;
  scheduleRefresh();
});
el.refreshNowBtn.addEventListener('click', () => refreshAll({ fresh: true, force: true }));
el.pauseBtn.addEventListener('click', () => {
  S.paused = !S.paused;
  S.monitorVersion++;
  el.pauseBtn.textContent = S.paused ? 'Resume connections' : 'Pause connections';
  el.pauseBtn.setAttribute('aria-pressed', String(S.paused));
  if (S.paused) disconnectTrafficStream();
  else { connectTrafficStream(); fetchConnections(); }
  updateListStatus();
  emit('stream:changed');
});
el.footRefresh.textContent = el.refreshSelect.selectedOptions[0].textContent;
initRadar();
initPanels();
initBlockedPanel();
initActions();
initConnectionList();
connectTrafficStream();
refreshAll();
scheduleRefresh();
// Host enrichment and firewall checks do not need the list's fast cadence.
setInterval(() => {
  if (!document.hidden) { fetchHostInfo(); fetchBlockedIPs(); }
}, 60000);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !S.paused) fetchConnections();
});

} else { showSessionRequired(); }
