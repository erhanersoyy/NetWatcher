import { Router } from 'express';
import { networkInterfaces, hostname } from 'node:os';
import { isIP } from 'node:net';
import { getConnections } from './connections.js';
import { lookupIPs, lookupSingleIP } from './geolocation.js';
import { reverseLookupBatch } from './dns-resolver.js';
import { getTrafficSnapshot, trafficKey } from './traffic.js';
import { subscribeTrafficStream, getLatestTrafficStats } from './traffic-stream.js';
import { getProcessMeta } from './process-info.js';
import { killProcess } from './process-kill.js';
import { vtLookup } from './virustotal.js';
import { blockIP, unblockIP, getBlockedIPs } from './firewall.js';
import { getBlockHistory, deleteBlockHistoryRow } from './block-store.js';
import type { ProcessInfo, EnrichedConnection, HostInfo } from './types.js';

export const router: ReturnType<typeof Router> = Router();

router.get('/api/connections', async (_req, res) => {
  const connections = await getConnections();

  // Collect unique remote IPs for batch geolocation + reverse DNS
  const uniqueIPs = [...new Set(connections.map((c) => c.remoteAddress))];
  // Prefer the live stream's snapshot when a client is subscribed — it's
  // always fresher than spawning a new one-shot. Fall back to a one-shot
  // for non-browser consumers (curl, tests) where no stream is running.
  const liveStats = getLatestTrafficStats();
  const trafficPromise = liveStats.size > 0
    ? Promise.resolve(liveStats)
    : getTrafficSnapshot();
  const [geoMap, dnsMap, trafficMap] = await Promise.all([
    lookupIPs(uniqueIPs),
    reverseLookupBatch(uniqueIPs),
    trafficPromise,
  ]);

  // Group by PID
  const processMap = new Map<number, ProcessInfo>();

  for (const conn of connections) {
    let proc = processMap.get(conn.pid);
    if (!proc) {
      const meta = getProcessMeta(conn.processName);
      proc = {
        pid: conn.pid,
        processName: conn.processName,
        description: meta.description,
        isSystemProcess: meta.isSystem,
        connections: [],
      };
      processMap.set(conn.pid, proc);
    }

    const protoFamily = conn.protocol.toLowerCase().startsWith('tcp') ? 'tcp' : 'udp';
    const key = trafficKey(
      protoFamily,
      conn.localAddress,
      conn.localPort,
      conn.remoteAddress,
      conn.remotePort,
    );
    const stats = trafficMap.get(key);

    const enriched: EnrichedConnection = {
      protocol: conn.protocol,
      remoteAddress: conn.remoteAddress,
      remotePort: conn.remotePort,
      localAddress: conn.localAddress,
      localPort: conn.localPort,
      state: conn.state,
      geo: geoMap.get(conn.remoteAddress) ?? null,
      domain: dnsMap.get(conn.remoteAddress) ?? '-',
      bytesIn: stats?.bytesIn,
      bytesOut: stats?.bytesOut,
    };
    proc.connections.push(enriched);
  }

  // No server-side sort — client controls sort order
  const result = [...processMap.values()];
  res.json(result);
});

router.post('/api/kill/:pid', async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  const result = await killProcess(pid);
  res.status(result.success ? 200 : 400).json(result);
});

router.get('/api/vt/:ip', async (req, res) => {
  const ip = req.params.ip;
  const result = await vtLookup(ip);
  res.status(result.success ? 200 : 500).json(result);
});

router.post('/api/block/:ip', async (req, res) => {
  const ip = req.params.ip;
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const result = await blockIP(ip, password);
  res.status(result.success ? 200 : 400).json(result);
});

router.post('/api/unblock/:ip', async (req, res) => {
  const ip = req.params.ip;
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const result = await unblockIP(ip, password);
  res.status(result.success ? 200 : 400).json(result);
});

/**
 * Live per-connection RX/TX byte stream. Server-Sent Events — one long-
 * running HTTP response, `event: delta` messages each second carrying
 * only the keys whose bytes changed. Client-side is plain EventSource.
 *
 * Backed by the traffic-stream singleton: the persistent `nettop` child
 * is spawned on first subscribe and torn down shortly after the last
 * client disconnects. CSRF-exempt because SSE is a read-only GET and
 * EventSource can't send custom headers; the Host/Origin allowlist in
 * `index.ts` still gates the request.
 */
router.get('/api/traffic-stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  const unsubscribe = subscribeTrafficStream((delta) => {
    // Express' res.write returns false on backpressure; we still want to
    // keep writing — EventSource will handle its own buffering.
    res.write(`event: delta\ndata: ${JSON.stringify(delta)}\n\n`);
  });

  // Comment frames keep proxies / the browser from timing the connection
  // out during long idle periods (no traffic = no deltas).
  const keepalive = setInterval(() => {
    res.write(': keepalive\n\n');
  }, 25000);

  const cleanup = (): void => {
    clearInterval(keepalive);
    unsubscribe();
    try { res.end(); } catch { /* already closed */ }
  };
  req.on('close', cleanup);
  req.on('error', cleanup);
});

router.get('/api/blocked', async (_req, res) => {
  const ips = await getBlockedIPs();
  res.json(ips);
});

router.get('/api/block-history', async (_req, res) => {
  const data = await getBlockHistory();
  res.json(data);
});

// Delete a single session (one row) from the block history.
// Query params:
//   blockedAt   (required) — ms timestamp of the block event
//   unblockedAt (optional) — ms timestamp of the paired unblock event;
//                            omit for 'superseded' rows where the row's
//                            end time is a different block event.
router.delete('/api/block-history/:ip', async (req, res) => {
  const ip = req.params.ip;
  if (isIP(ip) === 0) {
    res.status(400).json({ success: false, removed: 0, message: 'Invalid IP' });
    return;
  }
  const blockedAt = Number(req.query.blockedAt);
  if (!Number.isFinite(blockedAt)) {
    res.status(400).json({ success: false, removed: 0, message: 'blockedAt query param required' });
    return;
  }
  const rawUnblocked = req.query.unblockedAt;
  let unblockedAt: number | null = null;
  if (typeof rawUnblocked === 'string' && rawUnblocked.length > 0) {
    const parsed = Number(rawUnblocked);
    if (!Number.isFinite(parsed)) {
      res.status(400).json({ success: false, removed: 0, message: 'unblockedAt must be numeric' });
      return;
    }
    unblockedAt = parsed;
  }
  const result = await deleteBlockHistoryRow(ip, blockedAt, unblockedAt);
  res.status(result.success ? 200 : 400).json(result);
});

let cachedHostInfo: { data: HostInfo; timestamp: number } | null = null;
const HOST_INFO_TTL = 5 * 60 * 1000; // 5 minutes

router.get('/api/host-info', async (req, res) => {
  const bypassCache = req.query.fresh === '1';
  if (!bypassCache && cachedHostInfo && Date.now() - cachedHostInfo.timestamp < HOST_INFO_TTL) {
    res.json(cachedHostInfo.data);
    return;
  }

  // Get local IP
  const nets = networkInterfaces();
  let localIP = '127.0.0.1';
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] ?? []) {
      if (net.family === 'IPv4' && !net.internal) {
        localIP = net.address;
        break;
      }
    }
  }

  // Get public IP
  let publicIP = 'Unknown';
  let geo = null;
  try {
    const ipRes = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(5000) });
    const ipData = await ipRes.json() as { ip: string };
    publicIP = ipData.ip;
    geo = await lookupSingleIP(publicIP);
  } catch { /* ignore */ }

  const info: HostInfo = { localIP, publicIP, hostname: hostname(), geo };
  cachedHostInfo = { data: info, timestamp: Date.now() };
  res.json(info);
});
