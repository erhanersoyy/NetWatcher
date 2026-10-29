import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import type { Connection } from './types.js';

const execFileAsync = promisify(execFile);
function parseAddress(addr: string): { ip: string; port: number } | null {
  const match = addr.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
  if (!match) return null;
  const ip = match[1] || match[2], port = Number(match[3]);
  return isIP(ip) && port > 0 && port <= 65535 ? { ip, port } : null;
}

export function parseConnections(stdout: string): Connection[] {
  const connections: Connection[] = [];
  let pid = 0, name = '', protocol = '', state = '', address = '';
  const flush = () => {
    const [left, right] = address.split('->');
    const local = parseAddress(left ?? ''), remote = parseAddress(right ?? '');
    if (pid > 0 && local && remote && /^(TCP|UDP)$/.test(protocol)) {
      connections.push({ pid, processName: name, protocol, localAddress: local.ip, localPort: local.port,
        remoteAddress: remote.ip, remotePort: remote.port, state: state || 'UNKNOWN' });
    }
    protocol = state = address = '';
  };
  for (const line of stdout.split('\n')) {
    const value = line.slice(1);
    switch (line[0]) {
      case 'p': flush(); pid = /^\d+$/.test(value) ? Number(value) : 0; name = ''; break;
      case 'c': name = value; break;
      case 'f': flush(); break;
      case 'P': protocol = value; break;
      case 'T': if (value.startsWith('ST=')) state = value.slice(3); break;
      case 'n': address = value; break;
    }
  }
  flush(); // T fields may follow n: finish the complete FD before reading its state.
  return connections;
}

type LsofRunner = (file: string, args: string[], options: { timeout: number; maxBuffer: number }) => Promise<{ stdout: string; stderr: string }>;

export async function getConnections(run: LsofRunner = execFileAsync): Promise<Connection[]> {
  try {
    const { stdout } = await run('/usr/sbin/lsof', ['-i', '-n', '-P', '-F', 'pcPfTn'], {
      timeout: 5000, maxBuffer: 10 * 1024 * 1024,
    });
    return parseConnections(stdout);
  } catch (err) {
    const e = err as { code?: number; signal?: string; killed?: boolean; stderr?: string; stdout?: string };
    // lsof exits 1 for a successful selection with no matches. Every other failure is visible.
    if (e.code === 1 && !e.signal && !e.killed && !e.stderr?.trim() && !e.stdout?.trim()) return [];
    throw new Error('Connection collector unavailable (lsof failed or timed out); last snapshot is not current');
  }
}
