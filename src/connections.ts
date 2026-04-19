import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Connection } from './types.js';

const execFileAsync = promisify(execFile);

function parseAddress(addr: string): { ip: string; port: number } | null {
  if (!addr || addr === '*:*') return null;

  // IPv6: [::1]:port or [2607:f8b0:...]:port
  const ipv6Match = addr.match(/^\[(.+)\]:(\d+)$/);
  if (ipv6Match) {
    return { ip: ipv6Match[1], port: parseInt(ipv6Match[2], 10) };
  }

  // IPv4: 1.2.3.4:port
  const lastColon = addr.lastIndexOf(':');
  if (lastColon === -1) return null;
  const ip = addr.slice(0, lastColon);
  const port = parseInt(addr.slice(lastColon + 1), 10);
  if (isNaN(port)) return null;
  return { ip, port };
}

export async function getConnections(): Promise<Connection[]> {
  let stdout: string;
  try {
    const result = await execFileAsync('lsof', ['-i', '-n', '-P', '-F', 'pcPtTn'], {
      maxBuffer: 10 * 1024 * 1024,
    });
    stdout = result.stdout;
  } catch {
    return [];
  }

  const connections: Connection[] = [];
  let currentPid = 0;
  let currentName = '';
  let protocol = '';
  let state = '';

  const lines = stdout.split('\n');

  for (const line of lines) {
    if (!line) continue;

    const tag = line[0];
    const value = line.slice(1);

    switch (tag) {
      case 'p':
        currentPid = parseInt(value, 10);
        currentName = '';
        protocol = '';
        state = '';
        break;
      case 'c':
        currentName = value;
        break;
      case 'f':
        // New file descriptor — reset per-fd state
        protocol = '';
        state = '';
        break;
      case 'P':
        protocol = value;
        break;
      case 'T':
        if (value.startsWith('ST=')) {
          state = value.slice(3);
        }
        break;
      case 'n': {
        const arrowIdx = value.indexOf('->');
        if (arrowIdx === -1) break; // no remote connection (LISTEN, etc.)

        const local = parseAddress(value.slice(0, arrowIdx));
        const remote = parseAddress(value.slice(arrowIdx + 2));

        if (local && remote) {
          connections.push({
            pid: currentPid,
            processName: currentName,
            protocol,
            localAddress: local.ip,
            localPort: local.port,
            remoteAddress: remote.ip,
            remotePort: remote.port,
            state: state || 'UNKNOWN',
          });
        }
        break;
      }
    }
  }

  return connections;
}
