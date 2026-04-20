import { spawn } from 'node:child_process';

export interface TrafficStats {
  bytesIn: number;
  bytesOut: number;
}

/**
 * Build a lookup key for a connection:
 * `<proto>|<localIP>|<localPort>|<remoteIP>|<remotePort>`
 * IPv6 zone IDs (`%en0`) are stripped so keys match between lsof and nettop.
 */
export function trafficKey(
  protocol: string,
  localIP: string,
  localPort: number,
  remoteIP: string,
  remotePort: number,
): string {
  const p = protocol.toLowerCase();
  return `${p}|${normalizeIP(localIP)}|${localPort}|${normalizeIP(remoteIP)}|${remotePort}`;
}

/**
 * Normalize IPv6 so lsof and nettop representations collapse to the same key.
 *   lsof   link-local: `fe80:a::4cb:...`   (scope id embedded as hex group)
 *   nettop link-local: `fe80::4cb:...%en5` (scope id as %iface suffix)
 * Strip both forms to `fe80::4cb:...`.
 */
function normalizeIP(ip: string): string {
  let out = ip.replace(/%.+$/, '');
  out = out.replace(/^fe80:[0-9a-f]{1,4}::/i, 'fe80::');
  return out.toLowerCase();
}

function parseEndpoint(side: string, isIPv6: boolean): { ip: string; port: number } | null {
  // Skip wildcards
  if (side === '*:*' || side === '*.*') return null;

  const sepIdx = isIPv6 ? side.lastIndexOf('.') : side.lastIndexOf(':');
  if (sepIdx === -1) return null;

  const ip = side.slice(0, sepIdx).replace(/%.+$/, '');
  const portStr = side.slice(sepIdx + 1);
  if (ip === '*' || portStr === '*') return null;

  const port = parseInt(portStr, 10);
  if (isNaN(port)) return null;
  return { ip, port };
}

function parseConnectionLine(line: string): {
  key: string;
  bytesIn: number;
  bytesOut: number;
} | null {
  // Example: "tcp4 192.168.1.7:51927<->17.57.146.22:5223,88626,59471,"
  const spaceIdx = line.indexOf(' ');
  if (spaceIdx === -1) return null;

  const proto = line.slice(0, spaceIdx).toLowerCase();
  if (proto !== 'tcp4' && proto !== 'tcp6' && proto !== 'udp4' && proto !== 'udp6') {
    return null;
  }

  const rest = line.slice(spaceIdx + 1);
  const firstComma = rest.indexOf(',');
  if (firstComma === -1) return null;

  const endpoints = rest.slice(0, firstComma);
  const arrow = endpoints.indexOf('<->');
  if (arrow === -1) return null;

  const isIPv6 = proto === 'tcp6' || proto === 'udp6';
  const local = parseEndpoint(endpoints.slice(0, arrow), isIPv6);
  const remote = parseEndpoint(endpoints.slice(arrow + 3), isIPv6);
  if (!local || !remote) return null;

  const fields = rest.slice(firstComma + 1).split(',');
  const bytesIn = parseInt(fields[0] ?? '', 10);
  const bytesOut = parseInt(fields[1] ?? '', 10);
  if (isNaN(bytesIn) && isNaN(bytesOut)) return null;

  // Normalize protocol family to tcp/udp (lsof reports "TCP"/"UDP")
  const protoFamily = proto.startsWith('tcp') ? 'tcp' : 'udp';

  return {
    key: trafficKey(protoFamily, local.ip, local.port, remote.ip, remote.port),
    bytesIn: isNaN(bytesIn) ? 0 : bytesIn,
    bytesOut: isNaN(bytesOut) ? 0 : bytesOut,
  };
}

/**
 * Capture a single nettop snapshot (`-L 1`). Hierarchical output contains
 * per-process summary lines followed by per-connection lines; we only keep
 * the connection lines, keyed for merging with lsof-derived connections.
 */
export function getTrafficSnapshot(timeoutMs = 3000): Promise<Map<string, TrafficStats>> {
  return new Promise((resolve) => {
    const result = new Map<string, TrafficStats>();
    let settled = false;
    let buffer = '';

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
      resolve(result);
    };

    const child = spawn('nettop', ['-L', '1', '-nx', '-J', 'bytes_in,bytes_out'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });

    const timer = setTimeout(finish, timeoutMs);

    child.on('error', finish);
    child.on('close', () => {
      processBuffer(buffer, result, true);
      finish();
    });

    child.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      const lastNewline = buffer.lastIndexOf('\n');
      if (lastNewline === -1) return;
      const complete = buffer.slice(0, lastNewline);
      buffer = buffer.slice(lastNewline + 1);
      processBuffer(complete, result, false);
    });
  });
}

function processBuffer(text: string, out: Map<string, TrafficStats>, _final: boolean): void {
  const lines = text.split('\n');
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    // Connection lines always start with a protocol token + space
    if (!/^(tcp4|tcp6|udp4|udp6) /i.test(line)) continue;
    const parsed = parseConnectionLine(line);
    if (!parsed) continue;
    // nettop can report the same 5-tuple across multiple PIDs; sum them
    const existing = out.get(parsed.key);
    if (existing) {
      existing.bytesIn += parsed.bytesIn;
      existing.bytesOut += parsed.bytesOut;
    } else {
      out.set(parsed.key, { bytesIn: parsed.bytesIn, bytesOut: parsed.bytesOut });
    }
  }
}
