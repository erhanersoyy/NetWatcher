import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

// Parse the `sec = <epoch>` integer out of `sysctl -n kern.boottime` output,
// e.g. "{ sec = 1719300000, usec = 0 } Tue Jun 25 ..." -> 1719300000.
export function parseBootSec(output: string): number | null {
  const m = /sec\s*=\s*(\d+)/.exec(output);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

// System boot time in epoch seconds, read without sudo. Cached for the
// process lifetime — boot time is constant for a given OS boot. Only a
// successful read is cached, so a transient failure is retried next call.
// Returns null if sysctl is unavailable or its output can't be parsed
// (defense-in-depth; kern.boottime is world-readable on macOS).
let cached: number | null = null;
export async function getBootId(): Promise<number | null> {
  if (cached !== null) return cached;
  try {
    const { stdout } = await execFileAsync('sysctl', ['-n', 'kern.boottime'], { timeout: 5000 });
    const sec = parseBootSec(stdout);
    if (sec !== null) cached = sec;
    return sec;
  } catch {
    return null;
  }
}
