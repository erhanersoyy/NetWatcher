import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';

const execFileAsync = promisify(execFile);

interface VTCache {
  output: string;
  timestamp: number;
  analysisAt: string | null;
}

const cache = new Map<string, VTCache>();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

export function extractAnalysisDate(output: string): string | null {
  const match = output.match(/^\s*last_analysis_date:\s*(\d{10,11})\s*$/m);
  if (!match) return null;
  const time = Number(match[1]) * 1000;
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

export async function vtLookup(ip: string): Promise<{ success: boolean; output: string; queriedAt?: number; analysisAt?: string | null; cached?: boolean }> {
  if (isIP(ip) === 0) {
    return { success: false, output: 'Invalid IP address' };
  }

  const cached = cache.get(ip);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return { success: true, output: cached.output, queriedAt: cached.timestamp, analysisAt: cached.analysisAt, cached: true };
  }

  try {
    const { stdout, stderr } = await execFileAsync('vt', ['ip', ip, '--include=last_analysis_stats,last_analysis_date'], {
      timeout: 15000,
      maxBuffer: 1024 * 1024,
    });

    const output = stdout || stderr;
    const timestamp = Date.now(), analysisAt = extractAnalysisDate(output);
    cache.set(ip, { output, timestamp, analysisAt });
    return { success: true, output, queriedAt: timestamp, analysisAt, cached: false };
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && err.code === 'ENOENT') {
      return { success: false, output: 'VirusTotal CLI (vt) is not installed.\n\nInstall: brew install virustotal-cli\nThen configure: vt init' };
    }
    const message = err instanceof Error ? (err as { stderr?: string }).stderr || err.message : 'Unknown error';
    return { success: false, output: String(message) };
  }
}
