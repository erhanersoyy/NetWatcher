import { Router } from 'express';
import { networkInterfaces, hostname } from 'node:os';
import { getConnections } from './connections.js';
import { lookupIPs, lookupSingleIP } from './geolocation.js';
import { reverseLookupBatch } from './dns-resolver.js';
import { getProcessMeta } from './process-info.js';
import { killProcess } from './process-kill.js';
import { vtLookup } from './virustotal.js';
import { blockIP, unblockIP, getBlockedIPs } from './firewall.js';
import type { ProcessInfo, EnrichedConnection, HostInfo } from './types.js';

export const router: ReturnType<typeof Router> = Router();

router.get('/api/connections', async (_req, res) => {
  const connections = await getConnections();

  // Collect unique remote IPs for batch geolocation + reverse DNS
  const uniqueIPs = [...new Set(connections.map((c) => c.remoteAddress))];
  const [geoMap, dnsMap] = await Promise.all([
    lookupIPs(uniqueIPs),
    reverseLookupBatch(uniqueIPs),
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

    const enriched: EnrichedConnection = {
      protocol: conn.protocol,
      remoteAddress: conn.remoteAddress,
      remotePort: conn.remotePort,
      localAddress: conn.localAddress,
      localPort: conn.localPort,
      state: conn.state,
      geo: geoMap.get(conn.remoteAddress) ?? null,
      domain: dnsMap.get(conn.remoteAddress) ?? '-',
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
  const result = await blockIP(ip);
  res.status(result.success ? 200 : 400).json(result);
});

router.post('/api/unblock/:ip', async (req, res) => {
  const ip = req.params.ip;
  const result = await unblockIP(ip);
  res.status(result.success ? 200 : 400).json(result);
});

router.get('/api/blocked', async (_req, res) => {
  const ips = await getBlockedIPs();
  res.json(ips);
});

let cachedHostInfo: { data: HostInfo; timestamp: number } | null = null;
const HOST_INFO_TTL = 5 * 60 * 1000; // 5 minutes

router.get('/api/host-info', async (_req, res) => {
  if (cachedHostInfo && Date.now() - cachedHostInfo.timestamp < HOST_INFO_TTL) {
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
