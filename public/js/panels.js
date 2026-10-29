/* ============================================================
   NetWatcher — Panels subsystem
   Owns: throughput graph, system-health bars, clock.
   ============================================================ */

import { el } from './dom.js';
import { fmtBytes } from './util.js';
import { apiFetch } from './api.js';
import { S, on } from './state.js';

const { tRx, tTx, gRx, gTx, hCPU, hCPUbar, hMem, hMembar, hLoad, clockT, clockD, footTz } = el;

// ---------- Throughput history ----------
let rxHistory = Array(40).fill(0), txHistory = Array(40).fill(0);

export function clearThroughput() {
  tRx.textContent = tTx.textContent = '—';
  gRx.replaceChildren(); gTx.replaceChildren();
  rxHistory = Array(40).fill(0); txHistory = Array(40).fill(0);
}

function updateStreamStatus() {
  const recent = S.hasRateSample && S.lastDeltaAt && Date.now() - S.lastDeltaAt < 3000;
  el.statusText.textContent = S.paused ? 'Traffic · paused' : S.streamHealthy ? 'Traffic sampler · receiving' : 'Traffic sampler · unverified';
  el.statusText.classList.toggle('wait', S.paused || !recent);
  el.statusText.classList.toggle('err', !S.paused && !S.streamHealthy);
  el.trafficStatus.textContent = 'All monitored traffic · ' + (S.paused ? 'paused snapshot' : !S.streamHealthy
    ? 'no verified recent sample' : recent ? 'sampled rate · recent samples' : 'no recent samples (idle or unavailable)');
  if (!S.paused && (!recent || !S.streamHealthy)) clearThroughput();
}

export function pushThroughput(rxBps, txBps) {
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

// ---------- System health ----------
async function refreshSystemHealth() {
  try {
    const res = await apiFetch('/api/system-health');
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
    const [l1, l5, l15] = h.load;
    hLoad.textContent = `${l1.toFixed(2)} / ${l5.toFixed(2)} / ${l15.toFixed(2)}`;
    el.healthStatus.textContent = `Checked ${new Date().toLocaleTimeString()}`;
  } catch {
    el.healthStatus.textContent = 'Unavailable · values may be old';
  }
}

// ---------- Clock ----------
function tickClock() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  clockT.textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  const month = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getMonth()];
  clockD.textContent = `${p(d.getDate())} ${month} ${d.getFullYear()}`;
}

// ---------- initPanels: top-level setup called from main.js ----------
export function initPanels() {
  on('stream:changed', updateStreamStatus);
  setInterval(updateStreamStatus, 1000);
  // Clock
  setInterval(tickClock, 1000); tickClock();
  footTz.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // System health
  refreshSystemHealth();
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    refreshSystemHealth();
  }, 2200);

  // Preserve the existing density preference; the retired radar-off preference is ignored.
  try {
    const saved = JSON.parse(localStorage.getItem('nw-tweaks') || 'null');
    document.body.classList.toggle('density-comfortable', saved?.density === 'comfortable');
    document.body.classList.toggle('density-compact', saved?.density !== 'comfortable');
  } catch { /* Keep the default density. */ }
}
