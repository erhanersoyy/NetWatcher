// Isolated UI acceptance fixture: no OS commands, credentials, or data files.
// Run: node scripts/ui-preview.mjs — http://127.0.0.1:3857
// Use only dummy passwords. Every mutation returns a simulated failure.
// Optional: node --import tsx scripts/ui-preview.mjs --live-enrichment
// This checks real public-IP/geo/PTR services for public DNS endpoints only.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';

const root = fileURLToPath(new URL('../public/', import.meta.url));
const liveEnrichment = process.argv.includes('--live-enrichment')
  ? (await import('../src/geolocation.ts')).createEnrichmentService() : null;
const csp = (await readFile(new URL('../src/app.ts', import.meta.url), 'utf8')).match(/CONTENT_SECURITY_POLICY = "([^"]+)"/)[1];
let diagnostics = {};
const scenarios = ['unknown', 'stale', 'present', 'disabled', 'offline', 'empty', 'locked', 'radar', 'local', 'geo-pending', 'geo-limit', 'no-host', 'map-100', 'map-1000', 'map-10000', 'no-webgl'];
let scenario = 'unknown';
const clients = new Set();
const start = Date.now();
const geo = { country: 'Türkiye', countryCode: 'TR', city: 'Ankara', isp: 'Example ISP', lat: 39.9, lon: 32.8 };
const connection = (ip, n, extra = {}) => ({
  protocol: 'TCP', remoteAddress: ip, remotePort: 443, localAddress: '192.168.1.2',
  localPort: 5000 + n, state: 'ESTABLISHED', geo, domain: 'example.test',
  bytesIn: 1024 * 1024 * n, bytesOut: 1024 * n, trafficKey: `fixture-${n}`, ...extra,
});
const processes = [
  { pid: 101, processName: 'Example Browser', description: 'Fixture browser', isSystemProcess: false,
    connections: [connection('203.0.113.10', 1), connection('198.51.100.20', 2, { geo: null, domain: '' })] },
  { pid: 102, processName: 'Downloader with a deliberately long process name', description: 'Fixture download', isSystemProcess: false,
    connections: [connection('203.0.113.11', 3, { domain: 'a-long-hostname-for-layout-testing.example.test' })] },
  { pid: 103, processName: 'System fixture', description: 'Fixture only', isSystemProcess: true,
    connections: [connection('192.168.1.3', 4, { geo: null }), connection('2001:db8::1234', 5)] },
];
for (const proc of processes) proc.identity = { pid: proc.pid, parentPid: 1, uid: 501, startedAt: 'Thu Oct 29 07:35:40 2026', executable: `/Applications/${proc.processName}.app/Contents/MacOS/Example`, token: 'a'.repeat(64) };
for (const [i, proc] of processes.entries()) proc.verification = {
  state: 'complete', signature: ['valid', 'invalid', 'ad-hoc'][i],
  seal: i === 1 ? 'failed' : 'verified', signer: i === 0 ? 'Developer ID Application: Fixture Publisher' : null,
  teamId: i === 0 ? 'FIXTURE123' : null, sha256: String(i + 1).repeat(64),
  hashChanged: i === 1, checkedAt: start, detail: null,
};
const active = [10, 11].map((n, i) => ({ ip: `203.0.113.${n}`, country: geo.country,
  countryCode: geo.countryCode, isp: geo.isp, blockedAt: start - 60_000 * (i + 1), appliedBoot: 1 }));
const history = [...active.map(r => ({ ...r, action: 'block', at: r.blockedAt })),
  { ip: '198.51.100.30', action: 'block', at: start - 180_000, country: 'Example country' },
  { ip: '198.51.100.30', action: 'unblock', at: start - 120_000 }];
const json = (res, value, code = 200) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(value));
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:3857');
  res.setHeader('Content-Security-Policy', csp);
  if (url.pathname === '/__diagnostics' && req.method === 'GET') return json(res, diagnostics);
  if (url.pathname === '/__diagnostics' && req.method === 'POST') {
    let body = ''; for await (const chunk of req) { body += chunk; if (body.length > 100000) { res.writeHead(413); res.end(); return; } }
    try { diagnostics = JSON.parse(body); } catch {}
    return json(res, {ok:true});
  }
  if (url.pathname.startsWith('/__scenario/')) {
    const next = url.pathname.split('/').at(-1);
    if (!scenarios.includes(next)) return json(res, {}, 404);
    scenario = next; diagnostics = {};
    for (const client of clients) client.end();
    res.writeHead(303, { Location: '/' }); return res.end();
  }
  if (url.pathname.startsWith('/api/')) {
    if (url.pathname === '/api/session') { req.resume(); return json(res, { success: scenario !== 'locked' }, scenario === 'locked' ? 401 : 200); }
    if (req.method !== 'GET') {
      // Deliberately discard the body. Never log or forward a password.
      req.resume();
      return json(res, { success: false, message: 'Simulated operation failure. No system changes were made. Try again or cancel.' }, 400);
    }
    if (scenario === 'offline') return json(res, { message: 'Simulated offline service' }, 503);
    if (url.pathname === '/api/connections') {
      if (scenario.startsWith('map-')) {
        const count = Number(scenario.slice(4));
        return json(res, [{ ...processes[0], connections: Array.from({length: count}, (_, i) => connection(`198.18.${Math.floor(i / 256)}.${i % 256}`, i + 100, {
          geo: i % 10 ? { ...geo, lat: ((i * 137.5) % 150) - 75, lon: ((i * 97.3) % 360) - 180 } : null,
        })) }]);
      }
      const cities = [
        { country: 'United States', countryCode: 'US', city: 'New York', lat: 40.7, lon: -74 },
        { country: 'Germany', countryCode: 'DE', city: 'Frankfurt', lat: 50.1, lon: 8.6 },
        { country: 'Australia', countryCode: 'AU', city: 'Sydney', lat: -33.9, lon: 151.2 },
      ];
      return json(res, scenario === 'empty' ? [] : processes.map((p, i) => ({ ...p,
        connections: p.connections.map(c => {
          if (liveEnrichment) {
            const ip = ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888'][i];
            const location = liveEnrichment.geo(ip), domain = liveEnrichment.domain(ip);
            return { ...c, remoteAddress: ip, geo: location.value, domain: domain.value || '-', enrichment: { geo: location.state, dns: domain.state } };
          }
          return { ...c, geo: ['local', 'geo-pending', 'geo-limit'].includes(scenario) ? null : ['radar', 'no-host'].includes(scenario) ? { ...cities[i], isp: 'Fixture only' } : c.geo,
            enrichment: { geo: scenario === 'geo-limit' ? 'rate-limited' : scenario === 'geo-pending' ? 'pending' : 'ready', dns: 'ready' } };
        }),
      })));
    }
    if (url.pathname === '/api/host-info') return json(res, { hostname: 'UI TEST DATA', localIP: '192.168.1.2',
      ...(liveEnrichment ? await liveEnrichment.host(url.searchParams.get('fresh') === '1') : {
        publicIP: scenario === 'local' ? 'Unavailable' : '203.0.113.1', publicIPStatus: scenario === 'local' ? 'unavailable' : 'ready',
        geo: ['local', 'geo-pending', 'geo-limit', 'no-host'].includes(scenario) ? null : geo,
        geoStatus: scenario === 'geo-limit' ? 'rate-limited' : scenario === 'geo-pending' ? 'pending' : scenario === 'local' ? 'unavailable' : 'ready',
      }) });
    if (url.pathname === '/api/system-health') return json(res, { cpu: 18, memUsedBytes: 8e9, memTotalBytes: 16e9, load: [1, 1.1, 0.8] });
    if (url.pathname === '/api/firewall-status') return json(res, { checkedAt: Date.now(), pfEnabled: scenario === 'unknown' ? null : scenario !== 'disabled', anchorLinked: scenario === 'unknown' ? null : true, rulesPresent: scenario === 'unknown' ? null : true, tableIPs: ['present', 'disabled'].includes(scenario) ? [active[0].ip] : scenario === 'empty' ? [] : null, errors: [], trafficVerified: false });
    if (url.pathname === '/api/blocked') return json(res, scenario === 'present' ? [active[0].ip] : scenario === 'empty' ? [] : null);
    if (url.pathname === '/api/block-history') return json(res, {
      active: scenario === 'empty' ? [] : active, history: scenario === 'empty' ? [] : history,
      stale: scenario === 'stale', staleCount: scenario === 'stale' ? 2 : 0,
    });
    if (url.pathname === '/api/traffic-stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
      res.write('event: health\ndata: {"healthy":true}\n\n'); clients.add(res);
      req.on('close', () => clients.delete(res)); return;
    }
    if (url.pathname.startsWith('/api/vt/')) return json(res, { success: false, output: 'Simulated reputation service unavailable.' });
    return json(res, {}, 404);
  }
  if (url.pathname === '/__map-diagnostics.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript' });
    return res.end(await readFile(new URL('./map-diagnostics.js', import.meta.url)));
  }
  const file = resolve(root, '.' + (url.pathname === '/' ? '/index.html' : url.pathname));
  if (!file.startsWith(root.endsWith(sep) ? root : root + sep)) return json(res, {}, 404);
  try {
    let body = await readFile(file);
    if (extname(file) === '.html') {
      body = body.toString().replace('macOS network monitoring tool', 'UI TEST DATA · no system actions')
        .replace('<head>', `<head><script src="/__map-diagnostics.js?noGL=${scenario === 'no-webgl'}"></script>`)
        .replace('<div class="clock">', `<div class="clock"><nav aria-label="Test scenarios">${scenarios.map(s => `<a style="color:var(--ice);margin:4px" href="/__scenario/${s}">${s}</a>`).join('')}</nav>`);
    }
    res.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json' })[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
const timer = setInterval(() => {
  if (scenario === 'empty') return;
  const elapsed = Math.floor((Date.now() - start) / 1000);
  const delta = processes.flatMap(p => p.connections).map((c, i) => ({
    key: c.trafficKey, bytesIn: c.bytesIn + elapsed * (i + 1) * 100_000, bytesOut: c.bytesOut + elapsed * 1000,
  }));
  for (const client of clients) client.write(`event: delta\ndata: ${JSON.stringify(delta)}\n\n`);
}, 1000);
server.listen(3857, '127.0.0.1', () => console.log('UI fixture: http://127.0.0.1:3857 — dummy data, simulated mutations only'));
process.on('SIGINT', () => {
  liveEnrichment?.shutdown();
  clearInterval(timer);
  for (const client of clients) client.end();
  server.close();
});
