import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import { recordBlock, recordUnblock } from './block-store.js';
import { lookupSingleIP } from './geolocation.js';

const execFileAsync = promisify(execFile);

// Nested under the `com.apple/*` wildcard that macOS' main ruleset
// references (`anchor "com.apple/*" all` in /etc/pf.conf). A bare
// top-level anchor like "netwatcher" is loaded but never evaluated —
// nothing in the main ruleset descends into it, so pf processes every
// packet, hits no matching rule, and lets traffic through. Nesting
// under com.apple/* means pf automatically recurses into our rules.
// The `250.` numeric prefix keeps us away from Apple's own
// com.apple.<feature> anchors and pins evaluation order.
const ANCHOR = 'com.apple/250.netwatcher';
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

// Validate sudo credentials by running `sudo -v` (refresh timestamp, no command).
// Password is piped via stdin and never retained. `-p ''` suppresses the prompt
// so stderr stays clean. On success the sudo timestamp cache is primed so that
// subsequent `sudo -n pfctl` calls within this request don't need the password
// again. We never cache the password ourselves.
function validateSudo(password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('sudo', ['-S', '-p', '', '-v'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on('error', reject);
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('sudo timeout')); }, 5000);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error('sudo authentication failed (wrong password or sudo not permitted)'));
    });
    child.stdin.end(password + '\n');
  });
}

// Load anchor rules via `sudo -n pfctl -a <anchor> -f -`. Relies on a valid
// sudo timestamp (primed by validateSudo) — never receives the password itself.
function loadAnchorRules(rules: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('sudo', ['-n', '/sbin/pfctl', '-a', ANCHOR, '-f', '-'], {
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

  // Enable pf if not already. `-n` avoids a fresh password prompt; sudo timestamp
  // primed by validateSudo covers this call.
  try {
    await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-e']);
  } catch {
    // Already enabled — pfctl -e returns exit 1 if active; ignore.
  }

  // Clean up the legacy top-level `netwatcher` anchor from earlier versions.
  // It was never referenced by the main ruleset and therefore dormant, but
  // it can still contain stale table entries that show up in `pfctl -a
  // netwatcher -t netwatcher_block -T show`, leading to confusing state.
  try {
    await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-a', 'netwatcher', '-F', 'all'], { timeout: 5000 });
  } catch {
    // Legacy anchor may not exist; that's fine.
  }

  // macOS pf (FreeBSD 4.x-era) is strict about table references in the
  // `from` position — rules without explicit direction can fail to parse.
  // Always specify `in`/`out` and end with `\n` (pfctl expects a trailing newline).
  const rules =
    `table <${TABLE}> persist\n` +
    `block drop out quick from any to <${TABLE}>\n` +
    `block drop in  quick from <${TABLE}> to any\n`;

  try {
    await loadAnchorRules(rules);
    anchorInitialized = true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to initialize firewall anchor: ${msg}`);
  }
}

export async function blockIP(ip: string, password: string): Promise<{ success: boolean; message: string }> {
  if (!isBlockableIP(ip)) {
    return { success: false, message: 'Invalid or non-blockable IP address' };
  }
  if (typeof password !== 'string' || password.length === 0) {
    return { success: false, message: 'sudo password required' };
  }

  try {
    await validateSudo(password);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: msg };
  }

  try {
    await ensureAnchor();
    await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'add', ip], { timeout: 5000 });

    // Kill existing state-table entries for this IP. Without this, any
    // in-flight TCP/UDP flow (e.g. a download already in progress) keeps
    // passing via the state-table's cached `pass` verdict — pf never
    // re-evaluates rules for established state. Our block only affects
    // packets that miss the state table and go through rule evaluation.
    // A single `-k <ip>` matches states in either direction.
    try {
      await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-k', ip], { timeout: 5000 });
    } catch (err) {
      // Non-fatal: no matching states is not an error for our purposes.
      const msg = err instanceof Error ? err.message : String(err);
      if (!/No state/i.test(msg)) {
        console.warn(`[firewall] pfctl -k ${ip} warning:`, msg);
      }
    }

    // Record metadata out-of-band — pfctl's table has no notion of timestamps/country.
    try {
      const geo = await lookupSingleIP(ip);
      await recordBlock(ip, geo?.country ?? null);
    } catch {
      // If geo or store fails, the pf rule is already in place; don't fail the user action.
      await recordBlock(ip, null).catch(() => {});
    }
    return { success: true, message: `Blocked ${ip}` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to block ${ip}: ${msg}` };
  }
}

export async function unblockIP(ip: string, password: string): Promise<{ success: boolean; message: string }> {
  if (!isBlockableIP(ip)) {
    return { success: false, message: 'Invalid or non-blockable IP address' };
  }
  if (typeof password !== 'string' || password.length === 0) {
    return { success: false, message: 'sudo password required' };
  }

  try {
    await validateSudo(password);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: msg };
  }

  try {
    await ensureAnchor();
    await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'delete', ip], { timeout: 5000 });
    await recordUnblock(ip).catch(() => {});
    return { success: true, message: `Unblocked ${ip}` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to unblock ${ip}: ${msg}` };
  }
}

export async function getBlockedIPs(): Promise<string[]> {
  // Read-only; try non-interactively. If sudo timestamp isn't primed, return [].
  try {
    const { stdout } = await execFileAsync('sudo', ['-n', '/sbin/pfctl', '-a', ANCHOR, '-t', TABLE, '-T', 'show'], { timeout: 5000 });
    return stdout.split('\n').map(l => l.trim()).filter(Boolean);
  } catch {
    return [];
  }
}
