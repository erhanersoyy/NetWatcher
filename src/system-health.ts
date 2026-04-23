import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { loadavg, totalmem } from 'node:os';

const execFileAsync = promisify(execFile);

export interface SystemHealth {
  /**
   * Combined user+sys CPU percent as reported by macOS `top`. These values
   * are already normalized to whole-system percent (0–100) the same way
   * Activity Monitor displays them, NOT per-core aggregates. Clamped to
   * 100 to hide occasional transient overshoots under heavy load.
   */
  cpu: number | null;
  memUsedBytes: number | null;
  memTotalBytes: number;
  load: [number, number, number];
  tempC: number | null;        // null when unavailable (no sudo for powermetrics)
}

/**
 * Parse `top -l 1 -n 0` for CPU and memory. Sample output:
 *   CPU usage: 11.41% user, 19.23% sys, 69.34% idle
 *   PhysMem: 15G used (2757M wired, 6768M compressor), 80M unused.
 *
 * Units seen in `top` PhysMem line: B, K, M, G, T.
 */
function parseSizeToken(tok: string): number {
  const m = tok.match(/^(\d+(?:\.\d+)?)([BKMGT])?$/i);
  if (!m) return 0;
  const n = parseFloat(m[1]);
  const unit = (m[2] ?? 'B').toUpperCase();
  const mult: Record<string, number> = {
    B: 1,
    K: 1024,
    M: 1024 ** 2,
    G: 1024 ** 3,
    T: 1024 ** 4,
  };
  return n * (mult[unit] ?? 1);
}

function parseTop(out: string): { cpu: number | null; memUsed: number | null } {
  let cpu: number | null = null;
  let memUsed: number | null = null;

  const cpuMatch = out.match(/CPU usage:\s*([\d.]+)%\s*user,\s*([\d.]+)%\s*sys/i);
  if (cpuMatch) {
    cpu = Math.min(100, Math.max(0, parseFloat(cpuMatch[1]) + parseFloat(cpuMatch[2])));
  }

  // PhysMem: 15G used (...), 80M unused.
  const memMatch = out.match(/PhysMem:\s*([\d.]+[BKMGT]?)\s+used/i);
  if (memMatch) {
    memUsed = parseSizeToken(memMatch[1]);
  }

  return { cpu, memUsed };
}

/**
 * SoC temperature: intentionally unavailable without sudo. Apple's clean
 * reading requires `powermetrics` (sudo), and sudo-free paths are not
 * consistently reliable across hardware. UI renders null as "—".
 */
const TEMP_C: number | null = null;

export async function getSystemHealth(): Promise<SystemHealth> {
  const totalBytes = totalmem();
  const [one, five, fifteen] = loadavg();
  let cpu: number | null = null;
  let memUsed: number | null = null;

  try {
    // argv-form (no shell) + LC_ALL=C to keep `top`'s labels in English so
    // the regexes below match on non-English locales.
    const { stdout } = await execFileAsync('top', ['-l', '1', '-n', '0'], {
      timeout: 3000,
      env: { ...process.env, LC_ALL: 'C' },
    });
    const parsed = parseTop(stdout);
    cpu = parsed.cpu;
    memUsed = parsed.memUsed;
  } catch {
    // fall through — CPU/mem stay null; UI shows "—"
  }

  return {
    cpu,
    memUsedBytes: memUsed,
    memTotalBytes: totalBytes,
    load: [one, five, fifteen],
    tempC: TEMP_C,
  };
}
