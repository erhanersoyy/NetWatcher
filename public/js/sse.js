import { S, emit } from './state.js';
import { formatBytes, sampleRate } from './util.js';
import { pushThroughput, clearThroughput } from './panels.js';

let stream = null;
export function disconnectTrafficStream() {
  stream?.close();
  stream = null;
  S.streamHealthy = false;
  emit('stream:changed');
}

export function connectTrafficStream() {
  if (stream || S.paused) return;
  let es;
  try { es = new EventSource('/api/traffic-stream'); }
  catch { S.streamHealthy = false; emit('stream:changed'); return; }
  stream = es;
  es.addEventListener('open', () => {
    if (es !== stream) return;
    S.streamHealthy = false;
    S.streamConnectedAt = Date.now();
    S.lastDeltaAt = 0;
    S.hasRateSample = false;
    S.liveTraffic.clear(); // Never turn a reconnect gap into a traffic spike.
    clearThroughput();
    emit('stream:changed');
  });
  es.addEventListener('delta', (ev) => {
    if (es !== stream || S.paused) return;
    let entries;
    try { entries = JSON.parse(ev.data); } catch { return; }
    if (!Array.isArray(entries)) return;
    const now = Date.now();
    const seconds = S.lastDeltaAt ? Math.max((now - S.lastDeltaAt) / 1000, 0.1) : 0;
    let rx = 0, tx = 0;
    for (const value of S.liveTraffic.values()) { value.rxBps = 0; value.txBps = 0; }
    for (const entry of entries) {
      if (!entry || typeof entry.key !== 'string') continue;
      const bytesIn = Number(entry.bytesIn), bytesOut = Number(entry.bytesOut);
      if (!Number.isFinite(bytesIn) || !Number.isFinite(bytesOut) || bytesIn < 0 || bytesOut < 0) continue;
      const prev = S.liveTraffic.get(entry.key);
      const rxBps = sampleRate(prev?.bytesIn, bytesIn, seconds);
      const txBps = sampleRate(prev?.bytesOut, bytesOut, seconds);
      rx += rxBps; tx += txBps;
      S.liveTraffic.set(entry.key, { bytesIn, bytesOut, rxBps, txBps });
      for (const row of document.querySelectorAll(`.c[data-traffic-key="${CSS.escape(entry.key)}"]`)) {
        row.querySelector('[data-role="rx"]').textContent = `↓${formatBytes(bytesIn)}`;
        row.querySelector('[data-role="tx"]').textContent = `↑${formatBytes(bytesOut)}`;
      }
    }
    S.streamHealthy = true;
    S.lastDeltaAt = now;
    if (seconds) { S.hasRateSample = true; pushThroughput(rx, tx); }
    emit('traffic:changed');
    emit('stream:changed');
  });
  es.addEventListener('health', ev => {
    if (es !== stream) return;
    let health;
    try { health = JSON.parse(ev.data); } catch { return; }
    const healthy = health.healthy === true;
    if (!healthy) {
      S.lastDeltaAt = 0; S.hasRateSample = false;
      S.liveTraffic.clear(); clearThroughput();
    }
    S.streamHealthy = healthy;
    emit('stream:changed');
  });
  es.addEventListener('error', () => {
    if (es !== stream) return;
    S.streamHealthy = false;
    clearThroughput();
    emit('stream:changed');
    emit('traffic:changed');
  });
}
