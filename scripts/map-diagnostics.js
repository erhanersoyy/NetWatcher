// Loaded only by ui-preview.mjs; reports fixture-browser evidence to that server.
const diagnostics = { errors: [], csp: [], started: performance.now() };
if (document.currentScript.src.endsWith('noGL=true')) {
  const getContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function (type, ...args) {
    return type.startsWith('webgl') ? null : getContext.call(this, type, ...args);
  };
}
window.addEventListener('error', e => diagnostics.errors.push(e.message));
window.addEventListener('unhandledrejection', e => diagnostics.errors.push(String(e.reason)));
document.addEventListener('securitypolicyviolation', e => diagnostics.csp.push(`${e.violatedDirective}: ${e.blockedURI}`));
setInterval(() => {
  const status = document.getElementById('radarStatus');
  if (status?.hidden && !diagnostics.mapReadyMs) diagnostics.mapReadyMs = Math.round(performance.now());
  fetch('/__diagnostics', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
    ...diagnostics, mapStatus: status?.hidden ? 'ready' : status?.textContent,
    coverage: document.getElementById('mapCoverage')?.textContent,
    resources: performance.getEntriesByType('resource').map(r => r.name).filter(url => !url.includes('__diagnostics')),
    canvas: !!document.querySelector('.maplibregl-canvas'),
    targetButtons: document.querySelectorAll('.map-target').length,
  }) }).catch(() => {});
}, 2000);
