/* ============================================================
   NetWatcher — Panels subsystem
   Owns: throughput graph, system-health bars, clock, tweaks panel.
   ============================================================ */

import { el } from './dom.js';
import { fmtBytes } from './util.js';
import { apiFetch } from './api.js';
import { setRadarOn } from './radar.js';

const { tRx, tTx, gRx, gTx, hCPU, hCPUbar, hMem, hMembar, hLoad, clockT, clockD, footTz } = el;

// ---------- Throughput history ----------
let rxHistory = Array(40).fill(0), txHistory = Array(40).fill(0);

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
  } catch {
    // leave previous values in place on transient failure
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

// ---------- Tweaks ----------
const TWEAKS = JSON.parse(localStorage.getItem('nw-tweaks') || 'null') || { density: 'compact', radar: true };

function applyTweaks() {
  document.body.classList.toggle('density-compact', TWEAKS.density === 'compact');
  document.body.classList.toggle('density-comfortable', TWEAKS.density === 'comfortable');
  document.body.classList.toggle('radar-off', !TWEAKS.radar);
  setRadarOn(TWEAKS.radar !== false);
  for (const seg of document.querySelectorAll('.tweaks .seg')) {
    const k = seg.dataset.key;
    for (const b of seg.querySelectorAll('button')) b.classList.toggle('on', b.dataset.v === TWEAKS[k]);
  }
  document.getElementById('twRadar').classList.toggle('on', !!TWEAKS.radar);
  localStorage.setItem('nw-tweaks', JSON.stringify(TWEAKS));
}

// ---------- initPanels: top-level setup called from main.js ----------
export function initPanels() {
  // Clock
  setInterval(tickClock, 1000); tickClock();
  footTz.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // System health
  refreshSystemHealth();
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    refreshSystemHealth();
  }, 2200);

  // Tweaks handlers
  document.querySelectorAll('.tweaks .seg').forEach(seg => {
    seg.addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      TWEAKS[seg.dataset.key] = b.dataset.v;
      applyTweaks();
    });
  });
  document.getElementById('twRadar').addEventListener('click', () => {
    TWEAKS.radar = !TWEAKS.radar;
    applyTweaks();
  });
  applyTweaks();
}
