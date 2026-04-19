import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';

const execFileAsync = promisify(execFile);

const ANCHOR = 'netwatcher';
const TABLE = 'netwatcher_block';
let anchorInitialized = false;

// Reject IPs that would break local connectivity or are meaningless to block.
const FORBIDDEN_BLOCK_IPS = new Set([
  '0.0.0.0', '127.0.0.1', '255.255.255.255',
  '::', '::1',
]);

function isBlockableIP(ip: string): boolean {
  if (isIP(ip) === 0) return false;
  if (FORBIDDEN_BLOCK_IPS.has(ip)) return false;
  if (ip.startsWith('127.')) return false;
  return true;
}

function loadAnchorRules(rules: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('sudo', ['/sbin/pfctl', '-a', ANCHOR, '-f', '-'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on('error', reject);
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('pfctl timeout')); }, 5000);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `pfctl exited ${code}`));
    });
    child.stdin.end(rules);
  });
}

async function ensureAnchor(): Promise<void> {
  if (anchorInitialized) return;

  // Enable pf if not already
  try {
    await execFileAsync('sudo', ['/sbin/pfctl', '-e']);
  } catch {
    // Already enabled — pfctl -e returns exit 1 if already active
  }

  const rules = [
    `table <${TABLE}> persist`,
    `block drop quick from any to <${TABLE}>`,
    `block drop quick from <${TABLE}> to any`,
  ].join('\n');

  try {
    await loadAnchorRules(rules);
    anchorInitialized = true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to initialize firewall anchor: ${msg}. Run server with sudo or configure passwordless sudo for pfctl.`);
  }
}

export async function blockIP(ip: string): Promise<{ success: boolean; message: string }> {
  if (!isBlockableIP(ip)) {
    return { success: false, message: 'Invalid or non-blockable IP address' };
  }

  try {
    await ensureAnchor();
    await execFileAsync('sudo', ['/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'add', ip], { timeout: 5000 });
    return { success: true, message: `Blocked ${ip}` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to block ${ip}: ${msg}` };
  }
}

export async function unblockIP(ip: string): Promise<{ success: boolean; message: string }> {
  if (!isBlockableIP(ip)) {
    return { success: false, message: 'Invalid or non-blockable IP address' };
  }

  try {
    await ensureAnchor();
    await execFileAsync('sudo', ['/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'delete', ip], { timeout: 5000 });
    return { success: true, message: `Unblocked ${ip}` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to unblock ${ip}: ${msg}` };
  }
}

export async function getBlockedIPs(): Promise<string[]> {
  try {
    await ensureAnchor();
    const { stdout } = await execFileAsync('sudo', ['/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'show'], { timeout: 5000 });
    return stdout.split('\n').map(l => l.trim()).filter(Boolean);
  } catch {
    return [];
  }
}
