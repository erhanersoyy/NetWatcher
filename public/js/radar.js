/* ============================================================
   NetWatcher — Radar subsystem
   Self-contained: owns all canvas geometry, animation loop,
   country-border loader, and bus subscriptions.
   ============================================================ */

import { S, on } from './state.js';

// ---------- Canvas handle ----------
const radarCanvas = document.getElementById('radar');
const radarCtx = radarCanvas.getContext('2d');

// ---------- Geometry state ----------
let RW = 0, RH = 0, CX = 0, CY = 0, RR = 0;
let homeLat = null, homeLon = null;
let radarTargets = []; // { lat, lng, pt, hot, label, bytes, conns }
let sweepAngle = -Math.PI / 2;
let lastT = 0;
let radarOn = true;
// Pause the rAF loop when the radar isn't visible — tab hidden, scrolled
// out of view, or container display:none.
let radarVisible = true;
let radarTabVisible = !document.hidden;
let radarRafScheduled = false;

// Reduced-motion: freeze sweep, stop rAF loop self-scheduling.
const motionQuery = window.matchMedia ? matchMedia('(prefers-reduced-motion: reduce)') : null;

// Export so main.js's flashNewRows can read it without its own matchMedia call.
export const prefersReducedMotion = () => !!motionQuery?.matches;

// ---------- Country-border state ----------
let countryRings = null;            // Array<Array<[lng, lat]>> (raw lon/lat)
let projectedCountryRings = null;   // cached projected rings; rebuilt on home/size change

// ---------- Core helpers ----------
function radarShouldRun() { return radarOn && radarVisible && radarTabVisible; }

function scheduleRadarFrame() {
  if (radarRafScheduled || !radarShouldRun()) return;
  radarRafScheduled = true;
  requestAnimationFrame(radarFrame);
}

function sizeRadar() {
  const parent = radarCanvas.parentElement;
  const rect = parent.getBoundingClientRect();
  const w = Math.floor(rect.width);
  const h = Math.floor(rect.height);
  if (w === RW && h === RH) return;
  RW = w; RH = h;
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  radarCanvas.width = Math.floor(RW * dpr);
  radarCanvas.height = Math.floor(RH * dpr);
  radarCanvas.style.width = RW + 'px';
  radarCanvas.style.height = RH + 'px';
  radarCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  CX = Math.round(RW / 2);
  CY = Math.round(RH / 2);
  RR = Math.floor(Math.min(RW, RH) / 2) - 24;
  layoutBearings();
  reprojectTargets();
  reprojectCountryBorders();
}

function layoutBearings() {
  const wrap = document.getElementById('bearings');
  if (!wrap) return;
  wrap.innerHTML = '';
  const cardinals = [
    { l: 'N 000', a: -Math.PI / 2 },
    { l: 'NE 045', a: -Math.PI / 4 },
    { l: 'E 090', a: 0 },
    { l: 'SE 135', a: Math.PI / 4 },
    { l: 'S 180', a: Math.PI / 2 },
    { l: 'SW 225', a: 3 * Math.PI / 4 },
    { l: 'W 270', a: Math.PI },
    { l: 'NW 315', a: -3 * Math.PI / 4 },
  ];
  for (const c of cardinals) {
    const el = document.createElement('span');
    el.textContent = c.l;
    const r = RR + 20;
    el.style.left = (CX + Math.cos(c.a) * r) + 'px';
    el.style.top = (CY + Math.sin(c.a) * r) + 'px';
    wrap.appendChild(el);
  }
}

function project(lat, lng) {
  if (homeLat === null) return { x: CX, y: CY, c: 0 };
  const φ1 = homeLat * Math.PI / 180;
  const λ1 = homeLon * Math.PI / 180;
  const φ2 = lat * Math.PI / 180;
  const λ2 = lng * Math.PI / 180;
  const c = Math.acos(Math.max(-1, Math.min(1, Math.sin(φ1) * Math.sin(φ2) + Math.cos(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1))));
  const y = Math.sin(λ2 - λ1) * Math.cos(φ2);
  const x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1);
  const θ = Math.atan2(y, x);
  const rr = (c / Math.PI) * RR * 1.15;
  return { x: CX + rr * Math.sin(θ), y: CY - rr * Math.cos(θ), c };
}

function reprojectCountryBorders() {
  if (!countryRings || homeLat === null || RR <= 0) { projectedCountryRings = null; return; }
  projectedCountryRings = countryRings.map((ring) => ring.map(([lon, lat]) => project(lat, lon)));
}

function drawCountryBorders(ctx) {
  if (!projectedCountryRings) return;
  ctx.save();
  ctx.beginPath();
  ctx.arc(CX, CY, RR * 1.06, 0, Math.PI * 2);
  ctx.clip();
  ctx.strokeStyle = 'oklch(0.40 0.01 260 / 0.55)';
  ctx.lineWidth = 0.6;
  const CUTOFF = Math.PI * 0.92;
  for (const ring of projectedCountryRings) {
    ctx.beginPath();
    let prev = null;
    for (const p of ring) {
      if (p.c > CUTOFF) { prev = null; continue; }
      if (prev === null) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
      prev = p;
    }
    ctx.stroke();
  }
  ctx.restore();
}

function reprojectTargets() {
  for (const t of radarTargets) t.pt = project(t.lat, t.lng);
}

function radarSetHome(lat, lon) {
  if (typeof lat !== 'number' || typeof lon !== 'number') return;
  homeLat = lat; homeLon = lon;
  reprojectTargets();
  reprojectCountryBorders();
}

// Derive targets from S.lastData (bus-driven path). Applies same aggregation
// logic as the old renderQueue-driven path but reads directly from state.
function radarUpdateTargets(sortedProcs) {
  const seen = new Map();
  for (const p of sortedProcs) {
    for (const c of p.connections) {
      const g = c.geo;
      if (!g || g.country === 'Local' || (!g.lat && !g.lon)) continue;
      const key = `${g.lat.toFixed(2)},${g.lon.toFixed(2)}`;
      if (!seen.has(key)) {
        seen.set(key, {
          lat: g.lat, lng: g.lon,
          pt: project(g.lat, g.lng),
          hot: false,
          bytes: 0,
          label: `${g.countryCode || ''} · ${p.processName}`,
          conns: 0,
        });
      }
      const t = seen.get(key);
      const live = S.liveTraffic.get(c.trafficKey);
      t.bytes += (live ? live.bytesIn : (c.bytesIn || 0)) + (live ? live.bytesOut : (c.bytesOut || 0));
      t.conns += 1;
    }
  }
  const arr = [...seen.values()];
  arr.sort((a, b) => b.bytes - a.bytes);
  arr.forEach((t, i) => { t.hot = i < 3 && t.bytes > 0; });
  radarTargets = arr;
}

function radarFrame(ts) {
  radarRafScheduled = false;
  if (!radarShouldRun()) return;
  const reduceMotion = !!motionQuery?.matches;
  if (!reduceMotion) {
    requestAnimationFrame(radarFrame);
    radarRafScheduled = true;
  }
  if (!lastT) lastT = ts;
  const dt = (ts - lastT) / 1000; lastT = ts;
  if (!reduceMotion) {
    sweepAngle += dt * (Math.PI * 2 / 7);
    if (sweepAngle > Math.PI) sweepAngle -= Math.PI * 2;
  }

  const ctx = radarCtx;
  ctx.clearRect(0, 0, RW, RH);
  if (RR <= 0) return;

  // vignette
  const g = ctx.createRadialGradient(CX, CY, RR * 0.1, CX, CY, RR * 1.1);
  g.addColorStop(0, 'rgba(255,255,255,0.02)');
  g.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = g; ctx.fillRect(0, 0, RW, RH);

  drawCountryBorders(ctx);

  // rings
  ctx.strokeStyle = 'oklch(0.32 0.006 260)'; ctx.lineWidth = 1;
  for (const f of [0.25, 0.5, 0.75, 1.0]) {
    ctx.beginPath(); ctx.arc(CX, CY, RR * f, 0, Math.PI * 2); ctx.stroke();
  }
  ctx.strokeStyle = 'oklch(0.50 0.006 260)';
  ctx.beginPath(); ctx.arc(CX, CY, RR * 1.08, 0, Math.PI * 2); ctx.stroke();

  // crosshair
  ctx.strokeStyle = 'oklch(0.25 0.006 260)'; ctx.setLineDash([2, 4]);
  ctx.beginPath();
  ctx.moveTo(CX - RR * 1.05, CY); ctx.lineTo(CX + RR * 1.05, CY);
  ctx.moveTo(CX, CY - RR * 1.05); ctx.lineTo(CX, CY + RR * 1.05);
  const d = RR * 1.05 / Math.SQRT2;
  ctx.moveTo(CX - d, CY - d); ctx.lineTo(CX + d, CY + d);
  ctx.moveTo(CX - d, CY + d); ctx.lineTo(CX + d, CY - d);
  ctx.stroke(); ctx.setLineDash([]);

  // ticks
  ctx.strokeStyle = 'oklch(0.35 0.006 260)';
  for (let a = 0; a < 360; a += 5) {
    const rad = a * Math.PI / 180;
    const big = a % 15 === 0;
    const r1 = RR * 1.08, r2 = RR * (big ? 1.12 : 1.10);
    ctx.beginPath();
    ctx.moveTo(CX + Math.cos(rad) * r1, CY + Math.sin(rad) * r1);
    ctx.lineTo(CX + Math.cos(rad) * r2, CY + Math.sin(rad) * r2);
    ctx.stroke();
  }

  // home
  ctx.fillStyle = '#fff';
  ctx.beginPath(); ctx.arc(CX, CY, 3.5, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = 'rgba(255,255,255,0.4)';
  ctx.beginPath(); ctx.arc(CX, CY, 8 + Math.sin(ts / 400) * 2, 0, Math.PI * 2); ctx.stroke();

  // sweep cone + line
  const signal = 'oklch(0.74 0.25 340)';
  const grad = ctx.createRadialGradient(CX, CY, 0, CX, CY, RR * 1.08);
  grad.addColorStop(0, 'rgba(0,0,0,0)');
  grad.addColorStop(1, 'oklch(0.74 0.25 340 / 0.35)');
  ctx.save(); ctx.translate(CX, CY); ctx.rotate(sweepAngle);
  ctx.beginPath(); ctx.moveTo(0, 0);
  const spread = Math.PI / 5;
  ctx.arc(0, 0, RR * 1.08, -spread, 0); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();
  ctx.restore();

  ctx.save(); ctx.translate(CX, CY); ctx.rotate(sweepAngle);
  ctx.strokeStyle = signal; ctx.lineWidth = 1.4; ctx.shadowColor = signal; ctx.shadowBlur = 10;
  ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(RR * 1.08, 0); ctx.stroke();
  ctx.shadowBlur = 0; ctx.restore();

  // arcs
  ctx.strokeStyle = 'oklch(0.84 0.11 230 / 0.18)'; ctx.lineWidth = 0.8;
  for (const t of radarTargets) {
    ctx.beginPath();
    ctx.moveTo(CX, CY);
    const mx = (CX + t.pt.x) / 2, my = (CY + t.pt.y) / 2;
    const ndx = -(t.pt.y - CY), ndy = (t.pt.x - CX);
    const ln = Math.hypot(ndx, ndy) || 1;
    const k = 0.18;
    const cx2 = mx + ndx / ln * Math.hypot(t.pt.x - CX, t.pt.y - CY) * k;
    const cy2 = my + ndy / ln * Math.hypot(t.pt.x - CX, t.pt.y - CY) * k;
    ctx.quadraticCurveTo(cx2, cy2, t.pt.x, t.pt.y);
    ctx.stroke();
  }

  // targets
  for (const t of radarTargets) {
    const { x, y } = t.pt;
    const ang = Math.atan2(y - CY, x - CX);
    const rel = (sweepAngle - ang + Math.PI * 2) % (Math.PI * 2);
    const tail = Math.PI / 2.5;
    const illum = rel < tail ? 1 - rel / tail : 0;
    const baseAlpha = 0.55 + illum * 0.45;
    const color = t.hot ? 'oklch(0.74 0.25 340)' : 'oklch(0.84 0.11 230)';
    ctx.fillStyle = color; ctx.globalAlpha = baseAlpha;
    ctx.beginPath(); ctx.arc(x, y, t.hot ? 2.8 : 2.2, 0, Math.PI * 2); ctx.fill();
    if (illum > 0.2) {
      ctx.globalAlpha = illum * 0.6;
      ctx.strokeStyle = color; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(x, y, 6 + illum * 6, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }
}

// ---------- Public API ----------
// Allows main.js to toggle radar on/off without importing internals.
export function setRadarOn(enabled) {
  radarOn = enabled;
  if (radarOn) { lastT = 0; scheduleRadarFrame(); }
}

// Called by connection-list.js with the filtered+sorted list — same as the
// original app.js path. Keeps radar in sync with what's visible in the UI.
export function updateRadar(procs) {
  radarUpdateTargets(procs);
  scheduleRadarFrame();
}

// ---------- initRadar: top-level setup called from main.js ----------
export function initRadar() {
  // Initial size + first frame
  sizeRadar();
  scheduleRadarFrame();

  // Observers
  window.addEventListener('resize', sizeRadar);
  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(() => sizeRadar()).observe(radarCanvas.parentElement);
  }
  if (typeof IntersectionObserver !== 'undefined') {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        radarVisible = e.isIntersecting;
        if (radarVisible) { lastT = 0; scheduleRadarFrame(); }
      }
    }, { threshold: 0 });
    io.observe(radarCanvas);
  }

  // Motion / visibility listeners
  motionQuery?.addEventListener?.('change', () => { lastT = 0; scheduleRadarFrame(); });
  document.addEventListener('visibilitychange', () => {
    radarTabVisible = !document.hidden;
    lastT = 0;
    scheduleRadarFrame();
  });

  // Country-rings loader (reads window.topojson — global from SRI <script>)
  (async () => {
    try {
      const res = await fetch('https://unpkg.com/world-atlas@2.0.2/countries-110m.json');
      if (!res.ok) return;
      const topo = await res.json();
      const topojson = window.topojson;
      if (!topojson || !topo?.objects?.countries) return;
      const geo = topojson.feature(topo, topo.objects.countries);
      const rings = [];
      for (const feat of geo.features) {
        const geom = feat.geometry;
        if (!geom) continue;
        if (geom.type === 'Polygon') {
          for (const ring of geom.coordinates) rings.push(ring);
        } else if (geom.type === 'MultiPolygon') {
          for (const poly of geom.coordinates) {
            for (const ring of poly) rings.push(ring);
          }
        }
      }
      countryRings = rings;
      reprojectCountryBorders();
      scheduleRadarFrame();
    } catch {
      // CDN unavailable — radar renders without borders.
    }
  })();

  // Bus subscriptions — radar owns these
  on('host:changed', ({ lat, lon }) => radarSetHome(lat, lon));
}
