import { Router } from 'express';
import { networkInterfaces, hostname } from 'node:os';
import { isIP } from 'node:net';
import { getConnections } from './connections.js';
import { enrichment } from './geolocation.js';
import { trafficKey } from './traffic.js';
import { subscribeTrafficStream, getLatestTrafficStats, getSamplerHealth } from './traffic-stream.js';
import { getProcessMeta } from './process-info.js';
import { getProcessIdentities } from './process-identity.js';
import { processVerifier } from './process-verification.js';
import { killProcess } from './process-kill.js';
import { vtLookup } from './virustotal.js';
import { blockIP, unblockIP, getBlockedIPsOrNull, getFirewallStatus, reapplyBlocks } from './firewall.js';
import { getBlockHistory, deleteBlockHistoryRow, countStaleBlocks } from './block-store.js';
import { getBootId } from './boot-info.js';
import { getSystemHealth } from './system-health.js';
import { pickPrimaryIPv4 } from './net-iface.js';
import type { ProcessInfo, EnrichedConnection, HostInfo } from './types.js';

export const router: ReturnType<typeof Router> = Router();

// Share one collector run until it settles; slow callers cannot start overlapping lsof runs.
let connInFlight: Promise<ProcessInfo[]> | null = null;

async function buildConnectionsPayload(): Promise<ProcessInfo[]> {
  const before = await getProcessIdentities();
  const connections = await getConnections();

  // Schedule enrichment without awaiting external services.
  const uniqueIPs = [...new Set(connections.map((c) => c.remoteAddress))];
  const geoMap = new Map(uniqueIPs.map(ip => [ip, enrichment.geo(ip)]));
  const domainMap = new Map(uniqueIPs.map(ip => [ip, enrichment.domain(ip)]));
  const identities = await getProcessIdentities();
  const trafficMap = getLatestTrafficStats();

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
        identity: before.get(conn.pid)?.token === identities.get(conn.pid)?.token ? identities.get(conn.pid) ?? null : null,
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
      geo: geoMap.get(conn.remoteAddress)?.value ?? null,
      domain: domainMap.get(conn.remoteAddress)?.value ?? '-',
      enrichment: { geo: geoMap.get(conn.remoteAddress)!.state, dns: domainMap.get(conn.remoteAddress)!.state },
      bytesIn: stats?.bytesIn,
      bytesOut: stats?.bytesOut,
      trafficKey: key,
    };
    proc.connections.push(enriched);
  }

  // Only file metadata is awaited here. Codesign/hash run in a bounded queue;
  // subsequent connection polls pick up completed verification automatically.
  const processes = [...processMap.values()];
  await Promise.all(processes.map(async proc => {
    proc.verification = await processVerifier.inspect(proc.identity);
  }));
  // No server-side sort — client controls sort order
  return processes;
}

router.get('/api/connections', async (_req, res) => {
  if (!connInFlight) {
    const promise = buildConnectionsPayload().finally(() => {
      // Clear only if this entry is still the current one — a later poll
      // may have already replaced it, and we don't want to null that out.
      if (connInFlight === promise) connInFlight = null;
    });
    connInFlight = promise;
  }
  try {
    const result = await connInFlight;
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, message: (err as Error).message });
  }
});

router.post('/api/kill/:pid', async (req, res) => {
  const pid = /^\d+$/.test(req.params.pid) ? Number(req.params.pid) : NaN;
  const result = await killProcess(pid, req.body?.identityToken);
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

router.post('/api/reapply', async (req, res) => {
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const result = await reapplyBlocks(password);
  res.status(result.success ? 200 : 400).json(result);
});

/**
 * Live per-connection RX/TX byte stream. Server-Sent Events — one long-
 * running HTTP response, `event: delta` messages each second carrying
 * only the keys whose bytes changed. Client-side is plain EventSource.
 *
 * Backed by the traffic-stream singleton: the persistent `nettop` child
 * is spawned on first subscribe and torn down shortly after the last
 * client disconnects. A session cookie is mandatory, including on SSE. EventSource cannot send
 * the custom CSRF header; exact Host/Origin checks remain in app.ts.
 */
router.get('/api/traffic-stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  const unsubscribe = subscribeTrafficStream((delta) => {
    // Bound slow-client buffering; EventSource can reconnect with a fresh baseline.
    if (!res.write(`event: delta\ndata: ${JSON.stringify(delta)}\n\n`)) res.destroy();
  });

  const sendHealth = () => {
    if (!res.write(`event: health\ndata: ${JSON.stringify(getSamplerHealth())}\n\n`)) res.destroy();
  };
  sendHealth();
  const keepalive = setInterval(sendHealth, 2000);

  const cleanup = (): void => {
    clearInterval(keepalive);
    unsubscribe();
    try { res.end(); } catch { /* already closed */ }
  };
  req.on('close', cleanup);
  req.on('error', cleanup);
});

router.get('/api/system-health', async (_req, res) => {
  try {
    const health = await getSystemHealth();
    res.json(health);
  } catch (err) {
    res.status(500).json({ success: false, message: (err as Error).message });
  }
});

router.get('/api/firewall-status', async (_req, res) => { res.json(await getFirewallStatus()); });

router.get('/api/blocked', async (_req, res) => {
  // Returns the authoritative IP array when pfctl is readable, or JSON `null`
  // when it isn't (sudo timestamp not primed). The client treats null as
  // "unknown" and falls back to the persisted active list, rather than
  // mistaking an unreadable table for zero active blocks. We send null (200)
  // rather than a 503 so a sudo-less poll doesn't spam the console with errors.
  res.json(await getBlockedIPsOrNull());
});

router.get('/api/block-history', async (_req, res) => {
  // Pure read — no reconciliation. Reconciling against a live pfctl snapshot on
  // every poll was unsafe: after a reboot pfctl reports the table as gone (an
  // authoritative empty list), which fabricated bulk "unblock" events and
  // deleted still-wanted records; it also raced in-flight unblocks into
  // duplicate history rows and double-spawned pfctl per refresh. block/unblock
  // remain the authoritative mutators of the persisted store.
  //
  // `stale`/`staleCount` flag persisted-active blocks whose appliedBoot differs
  // from the current boot (almost certainly wiped by a reboot). currentBoot is
  // read without sudo; if it's unreadable we report 0 (no false-alarm banner).
  const data = await getBlockHistory();
  const currentBoot = await getBootId();
  const staleCount = currentBoot == null ? 0 : countStaleBlocks(data.active, currentBoot);
  res.json({ ...data, stale: staleCount > 0, staleCount });
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

router.get('/api/host-info', async (req, res) => {
  // Get local IP (prefers en*, skips VPN/Docker/virtual interfaces)
  const localIP = pickPrimaryIPv4(networkInterfaces());
  const info: HostInfo = { localIP, hostname: hostname(), ...await enrichment.host(req.query.fresh === '1') };
  res.json(info);
});
