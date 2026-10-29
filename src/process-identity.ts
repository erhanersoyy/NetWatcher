import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
const execFileAsync = promisify(execFile);

export interface ProcessIdentity {
  pid: number;
  parentPid: number;
  uid: number;
  startedAt: string;
  executable: string;
  token: string;
}

export function parseIdentities(output: string): Map<number, ProcessIdentity> {
  const result = new Map<number, ProcessIdentity>();
  for (const line of output.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+?)\s*$/);
    if (!m) continue;
    const [pid, parentPid, uid] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const startedAt = m[4].replace(/\s+/g, ' '), executable = m[5];
    const token = createHash('sha256').update(JSON.stringify([pid, uid, startedAt, executable])).digest('hex');
    result.set(pid, { pid, parentPid, uid, startedAt, executable, token });
  }
  return result;
}

export async function getProcessIdentities(pid?: number): Promise<Map<number, ProcessIdentity>> {
  try {
    const { stdout } = await execFileAsync('/bin/ps', [...(pid === undefined ? ['-ax'] : ['-p', String(pid)]), '-o', 'pid=,ppid=,uid=,lstart=,comm='], {
      timeout: 3000, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, LC_ALL: 'C' },
    });
    return parseIdentities(stdout);
  } catch { return new Map(); }
}
