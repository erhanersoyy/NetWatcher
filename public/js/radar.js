/* Connection map: local MapLibre renderer, linked to the existing process list. */
import { S, on, emit } from './state.js';
import { escapeHtml, formatBytes } from './util.js';
import { collectTargets, mapRatesAvailable, targetFeatures, validGeo, prepareCountryAtlas } from './radar-data.js';

const motionQuery = window.matchMedia?.('(prefers-reduced-motion: reduce)');
export const prefersReducedMotion = () => !!motionQuery?.matches;
const $ = id => document.getElementById(id);
const empty = () => ({ type: 'FeatureCollection', features: [] });
let map, ready = false, failed = false, targets = [], sourceSignature = '', geometryVersion = 0;
let sourceBusy = false, pendingSource = null, disposed = false;
let visible = true, pendingDraw = false, listLimit = 50, lastListSignature = '';
let targetScope = 'all';
let lastHighlightSignature = '', rateStates = new Map();
let atlasAvailable = true;

function notice(message) {
  $('radarStatus').textContent = message;
  $('radarStatus').hidden = !message;
}
function updateStatus() {
  const located = targets.filter(t => t.geo).length;
  $('mapCoverage').textContent = `${located}/${targets.length} targets located · ${targets.length - located} unknown`;
  const updated = S.connectionsUpdatedAt ? new Date(S.connectionsUpdatedAt).toLocaleTimeString() : '—';
  const stale = S.connectionsError || (S.connectionsUpdatedAt && Date.now() - S.connectionsUpdatedAt > Math.max(30000, S.refreshIntervalMs * 2));
  $('mapSampleStatus').textContent = `${S.paused ? 'Paused' : stale ? 'Stale snapshot' : mapRatesAvailable(S) ? 'Live rates' : 'Rates unavailable'} · list ${updated}`;
  if (failed) notice('Map unavailable. Select a target from the list below.');
  else if (!ready) notice('Loading map…');
  else if (!atlasAvailable) notice('Country boundaries unavailable. Connection targets remain selectable.');
  else if (!S.lastData) notice('Waiting for a connection snapshot…');
  else if (!targets.length) notice('No targets in the current filters.');
  else if (!located) notice('Locations unavailable. All targets remain in the list below.');
  else notice('');
  const selected = S.mapSelection;
  const selectedIPs = new Set(selected?.ips || []);
  const currentCount = targets.filter(t => selectedIPs.has(t.ip)).length;
  const proc = targets.flatMap(t => t.processes).find(p => p.key === S.mapProcess);
  $('mapSelectionBar').hidden = !selected && !proc;
  $('mapInspect').hidden = !selected;
  $('mapSelectionLabel').textContent = selected
    ? `${selected.label} · ${currentCount} current target${currentCount === 1 ? '' : 's'} · process list filtered`
    : proc ? `${proc.name} · PID ${proc.pid} · targets highlighted` : '';
  $('mapInspect').disabled = !!selected && !currentCount;
}
function renderTargets() {
  const list = $('mapTargets');
  const selected = new Set(S.mapSelection?.ips || []);
  const scoped = targets.filter(t => targetScope !== 'unknown' || !t.geo);
  const shown = scoped.slice(0, listLimit);
  $('mapTargetCount').textContent = `${Math.min(listLimit, scoped.length)} of ${scoped.length}`;
  $('mapMore').hidden = scoped.length <= listLimit;
  const structure = JSON.stringify([shown.map(t => [t.ip, t.geo?.city, t.geo?.country, t.processes, t.connections]), [...selected], S.mapProcess]);
  if (structure !== lastListSignature) {
    const focused = list.contains(document.activeElement) ? document.activeElement?.dataset.ip : null;
    const scroll = list.scrollTop;
    list.innerHTML = shown.map(t => {
      const names = t.processes.map(p => `${p.name} (PID ${p.pid})`).join(', ');
      const place = t.geo ? [t.geo.city, t.geo.country].filter(Boolean).join(', ') : 'Location unknown';
      return `<button class="map-target${t.processes.some(p => p.key === S.mapProcess) ? ' highlighted' : ''}" data-ip="${escapeHtml(t.ip)}" aria-pressed="${selected.has(t.ip)}" aria-label="Select ${escapeHtml(t.ip)}. ${escapeHtml(place)}. ${t.processes.length} process${t.processes.length === 1 ? '' : 'es'}.">
        <span class="map-target-ip">${escapeHtml(t.ip)}</span><span class="map-target-place">${escapeHtml(place)}</span>
        <span class="map-target-process" title="${escapeHtml(names)}">${escapeHtml(t.processes[0]?.name || '')}${t.processes.length > 1 ? ` +${t.processes.length - 1} processes` : ''} · ${t.connections} connection${t.connections === 1 ? '' : 's'}</span>
        <span class="map-target-rate"></span></button>`;
    }).join('') || '<p class="map-empty">No targets in this view.</p>';
    lastListSignature = structure;
    if (focused) (list.querySelector(`[data-ip="${CSS.escape(focused)}"]`) || $('mapTargetScope').querySelector('[aria-pressed="true"]')).focus({ preventScroll: true });
    list.scrollTop = scroll;
  }
  for (const [i, button] of [...list.querySelectorAll('.map-target')].entries()) {
    const target = shown[i], rate = button.querySelector('.map-target-rate');
    rate.classList.toggle('unavailable', target.txBps === null);
    rate.textContent = target.txBps === null ? '↑ —/s' : `↑ ${formatBytes(target.txBps)}/s`;
    button.title = `${target.processes.map(p => `${p.name} (PID ${p.pid})`).join(', ')} · Received ${target.bytesIn === null ? '—' : formatBytes(target.bytesIn)} · Sent ${target.bytesOut === null ? '—' : formatBytes(target.bytesOut)}`;
  }
}
function choose(ips, label, focus = false) {
  S.mapSelection = { ips: [...new Set(ips)], label };
  S.mapProcess = null;
  emit('map:selection');
  draw();
  if (focus) focusTargets(targets.filter(t => ips.includes(t.ip)));
}
function clearSelection() {
  S.mapSelection = null;
  S.mapProcess = null;
  emit('map:selection');
  draw();
  $('mapTargetScope').querySelector('[aria-pressed="true"]').focus({ preventScroll: true });
}

function updateHighlights() {
  if (!ready) return;
  const ips = new Set(S.mapSelection?.ips || []);
  const selected = targetFeatures(targets.filter(t => ips.has(t.ip) || t.processes.some(p => p.key === S.mapProcess)));
  const sig = JSON.stringify(selected);
  if (sig === lastHighlightSignature) return;
  lastHighlightSignature = sig;
  map.getSource('selected').setData(selected).catch(() => {});
}
function updateRates() {
  if (!ready) return;
  const next = new Map();
  for (const target of targets) {
    if (!target.geo) continue;
    next.set(target.ip, target.txBps);
    if (rateStates.has(target.ip) && rateStates.get(target.ip) === target.txBps) continue;
    map.setFeatureState({ source: 'targets', id: target.ip }, { txBps: target.txBps ?? 0, hasRate: target.txBps !== null });
  }
  for (const ip of rateStates.keys()) if (!next.has(ip)) map.removeFeatureState({ source: 'targets', id: ip });
  rateStates = next;
}
async function flushSource() {
  if (sourceBusy || !ready || !pendingSource) return;
  sourceBusy = true;
  const data = pendingSource;
  pendingSource = null;
  try {
    await map.getSource('targets').setData(data);
    rateStates.clear();
    if (!disposed && ready) updateRates();
  } catch {
    if (!disposed) failMap();
  } finally {
    sourceBusy = false;
    if (!disposed) flushSource();
  }
}
function draw() {
  if (!visible || document.hidden) { pendingDraw = true; return; }
  pendingDraw = false;
  updateStatus();
  renderTargets();
  if (!ready) return;
  const data = targetFeatures(targets), signature = JSON.stringify(data);
  if (signature !== sourceSignature) {
    sourceSignature = signature;
    geometryVersion++;
    pendingSource = data;
    flushSource();
  } else if (!sourceBusy) updateRates();
  updateHighlights();
}
export function updateRadar(processes) {
  targets = collectTargets(processes, S.liveTraffic, mapRatesAvailable(S));
  draw();
}
function updateHome() {
  if (!ready) return;
  const geo = S.hostInfo?.geo;
  map.getSource('home').setData(validGeo(geo) ? targetFeatures([{ ip: 'home', geo }]) : empty()).catch(() => {});
}
function resetWorld() {
  if (!ready) return;
  map.fitBounds([[-180, -60], [180, 80]], { padding: 24, duration: 0 });
}
function focusTargets(items) {
  if (!ready) return;
  const coordinates = targetFeatures(items).features.map(f => f.geometry.coordinates);
  if (!coordinates.length) return;
  const lons = coordinates.map(c => c[0]), lats = coordinates.map(c => c[1]);
  map.fitBounds([[Math.min(...lons), Math.min(...lats)], [Math.max(...lons), Math.max(...lats)]],
    { padding: 48, maxZoom: 4, duration: prefersReducedMotion() ? 0 : 250 });
}
function failMap() {
  failed = true;
  ready = false;
  $('mapReset').disabled = true;
  notice('Map unavailable. Select a target from the list below.');
}

async function loadMap() {
  try {
    const [lib, countries] = await Promise.all([
      import('../vendor/maplibre-6.16.0/maplibre-gl.mjs'),
      fetch('/vendor/countries-110m.json').then(r => { if (!r.ok) throw Error('atlas'); return r.json(); })
        .then(topology => prepareCountryAtlas(window.topojson.feature(topology, topology.objects.countries)))
        .catch(() => { atlasAvailable = false; return empty(); }),
    ]);
    if (disposed) return;
    lib.setWorkerUrl(new URL('../vendor/maplibre-6.16.0/maplibre-gl-worker.mjs', import.meta.url).href);
    lib.setWorkerCount(1);
    map = new lib.Map({
      container: 'radar', center: [15, 20], zoom: 0, minZoom: 0, maxZoom: 6,
      renderWorldCopies: false, dragRotate: false, pitchWithRotate: false, touchPitch: false,
      fadeDuration: 0, attributionControl: false, cooperativeGestures: true,
      style: { version: 8, transition: { duration: 0, delay: 0 }, sources: {
        countries: { type: 'geojson', data: countries },
        targets: { type: 'geojson', data: empty(), promoteId: 'ip', cluster: true, clusterRadius: 40, clusterMaxZoom: 5 },
        selected: { type: 'geojson', data: empty() }, home: { type: 'geojson', data: empty() },
      }, layers: [
        { id: 'ocean', type: 'background', paint: { 'background-color': '#101820' } },
        { id: 'land', type: 'fill', source: 'countries', paint: { 'fill-color': '#253544' } },
        { id: 'borders', type: 'line', source: 'countries', paint: { 'line-color': '#536575', 'line-width': 0.6 } },
        { id: 'clusters', type: 'circle', source: 'targets', filter: ['has', 'point_count'], paint: {
          'circle-color': '#376075', 'circle-stroke-color': '#9edcf3', 'circle-stroke-width': 1.5,
          'circle-radius': ['step', ['get', 'point_count'], 17, 10, 22, 100, 28],
        } },
        { id: 'cluster-count', type: 'symbol', source: 'targets', filter: ['has', 'point_count'], layout: {
          'text-field': ['get', 'point_count_abbreviated'], 'text-font': ['sans-serif'], 'text-size': 12, 'text-allow-overlap': true,
        }, paint: { 'text-color': '#f1f8fc' } },
        { id: 'points', type: 'circle', source: 'targets', filter: ['!', ['has', 'point_count']], paint: {
          'circle-color': ['case', ['boolean', ['feature-state', 'hasRate'], false], '#e988c8', '#a5b4c1'],
          'circle-radius': ['interpolate', ['linear'], ['coalesce', ['feature-state', 'txBps'], 0], 0, 5, 1024, 7, 1048576, 13, 10485760, 20],
          'circle-stroke-width': 1.5, 'circle-stroke-color': '#f4f7fa',
        } },
        { id: 'selection', type: 'circle', source: 'selected', paint: { 'circle-radius': 23, 'circle-color': '#96dcfa', 'circle-opacity': 0.12, 'circle-stroke-color': '#96dcfa', 'circle-stroke-width': 2 } },
        { id: 'home-dot', type: 'circle', source: 'home', paint: { 'circle-radius': 4, 'circle-color': '#9edcf3', 'circle-stroke-color': '#101820', 'circle-stroke-width': 2 } },
        { id: 'home-label', type: 'symbol', source: 'home', layout: { 'text-field': 'Public IP', 'text-font': ['sans-serif'], 'text-size': 11, 'text-offset': [0, 1.5] }, paint: { 'text-color': '#b4d9ea', 'text-halo-color': '#101820', 'text-halo-width': 2 } },
      ] },
    });
    map.touchZoomRotate.disableRotation();
    map.addControl(new lib.NavigationControl({ showCompass: false }), 'top-right');
    map.addControl(new lib.AttributionControl({ compact: false, customAttribution: 'Natural Earth' }));
    map.getCanvas().setAttribute('aria-label', 'World connection map. Use arrow keys to pan and plus or minus to zoom. Select targets in the list below.');
    map.on('error', () => { if (!ready) failMap(); });
    map.on('webglcontextlost', failMap);
    map.on('webglcontextrestored', () => {
      failed = false; ready = true; sourceSignature = ''; lastHighlightSignature = ''; rateStates.clear();
      $('mapReset').disabled = false; updateHome(); draw();
    });
    map.on('load', () => {
      ready = true; failed = false; $('mapReset').disabled = false;
      resetWorld(); updateHome(); draw();
    });
    map.on('click', async e => {
      const feature = map.queryRenderedFeatures(e.point, { layers: ['clusters', 'points'] })[0];
      if (!feature) return;
      if (!feature.properties.cluster) {
        choose([feature.properties.ip], feature.properties.ip);
        return;
      }
      const version = geometryVersion;
      try {
        const source = map.getSource('targets'), id = feature.properties.cluster_id;
        const [leaves, zoom] = await Promise.all([
          source.getClusterLeaves(id, feature.properties.point_count, 0), source.getClusterExpansionZoom(id),
        ]);
        if (version !== geometryVersion || disposed) return;
        choose(leaves.map(f => f.properties.ip), `${leaves.length} target cluster`);
        map.easeTo({ center: feature.geometry.coordinates, zoom: Math.min(zoom, 6), duration: prefersReducedMotion() ? 0 : 250 });
      } catch { /* Cluster changed while a newer snapshot was arriving; keep the current selection. */ }
    });
    for (const layer of ['clusters', 'points']) {
      map.on('mouseenter', layer, () => { map.getCanvas().style.cursor = 'pointer'; });
      map.on('mouseleave', layer, () => { map.getCanvas().style.cursor = ''; });
    }
  } catch { failMap(); }
}

export function initRadar() {
  $('mapReset').disabled = true;
  $('mapReset').addEventListener('click', resetWorld);
  $('mapExpand').addEventListener('click', () => {
    const expanded = $('connectionMap').classList.toggle('enlarged');
    $('mapExpand').setAttribute('aria-expanded', String(expanded));
    $('mapExpand').textContent = expanded ? 'Reduce' : 'Enlarge';
    map?.resize();
  });
  $('mapClear').addEventListener('click', clearSelection);
  $('mapInspect').addEventListener('click', () => emit('map:inspect'));
  $('mapTargetScope').addEventListener('click', e => {
    const button = e.target.closest('[data-scope]');
    if (!button) return;
    targetScope = button.dataset.scope;
    for (const item of $('mapTargetScope').querySelectorAll('button')) item.setAttribute('aria-pressed', String(item === button));
    listLimit = 50;
    renderTargets();
  });
  $('mapMore').addEventListener('click', () => { listLimit += 50; renderTargets(); });
  $('mapTargets').addEventListener('click', e => {
    const ip = e.target.closest('[data-ip]')?.dataset.ip;
    if (ip) choose([ip], ip, true);
  });
  on('host:changed', updateHome);
  on('map:process', () => { draw(); focusTargets(targets.filter(t => t.processes.some(p => p.key === S.mapProcess))); });
  on('stream:changed', () => { updateStatus(); });
  new ResizeObserver(() => map?.resize()).observe($('mapViewport'));
  new IntersectionObserver(entries => {
    visible = entries[0].isIntersecting;
    if (visible && pendingDraw) draw();
  }).observe($('connectionMap'));
  document.addEventListener('visibilitychange', () => { if (!document.hidden) draw(); });
  window.addEventListener('pagehide', event => { if (!event.persisted) { disposed = true; ready = false; map?.remove(); } });
  loadMap();
}
