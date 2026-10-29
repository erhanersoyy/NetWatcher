import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import { safeEndStdin } from './proc-io.js';
import { recordBlock, recordUnblock, markReapplied, getBlockHistory } from './block-store.js';
import { getBootId } from './boot-info.js';
import { canonicalIP } from './ip-address.js';
export { canonicalIP } from './ip-address.js';
import type { ActionResult } from './types.js';

const execFileAsync = promisify(execFile);
const ANCHOR = 'com.apple/250.netwatcher';
const TABLE = 'netwatcher_block';
const RULES = `table <${TABLE}> persist\nblock drop out quick from any to <${TABLE}>\nblock drop in quick from <${TABLE}> to any\n`;

export interface FirewallStatus {
  checkedAt: number;
  pfEnabled: boolean | null;
  anchorLinked: boolean | null;
  rulesPresent: boolean | null;
  tableIPs: string[] | null;
  errors: string[];
  trafficVerified: false;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function isBlockableIP(ip: string): boolean {
  if (!isIP(ip) || ip.includes('%')) return false;
  const normalized = canonicalIP(ip);
  if (['0.0.0.0', '255.255.255.255', '::', '::1'].includes(normalized)) return false;
  if (normalized.startsWith('127.')) return false;
  // Apply the same restrictions to IPv4-mapped IPv6 forms, including hex notation.
  const mapped = normalized.match(/^::ffff:([\da-f]+):([\da-f]+)$/);
  if (mapped) {
    const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
    return isBlockableIP(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  return true;
}

function sudoInput(args: string[], input: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/sudo', args, { stdio: ['pipe', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => { stderr = (stderr + chunk.toString()).slice(-4096); });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('sudo/pfctl timeout')); }, 5000);
    child.on('error', err => { clearTimeout(timer); reject(err); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(args.includes('-v') ? 'sudo authentication failed' : stderr.trim() || `pfctl exited ${code}`));
    });
    safeEndStdin(child, input);
  });
}

async function authenticate(password: string): Promise<void> {
  // -k with -v ignores cached credentials, but does NOT update the cache.
  // Only after fresh authentication succeeds, prime it for this serialized operation.
  // Neither call invalidates another terminal's timestamp or logs the password.
  await sudoInput(['-S', '-k', '-p', '', '-v'], password + '\n');
  await sudoInput(['-S', '-p', '', '-v'], password + '\n');
}

interface FirewallDependencies {
  authenticate: typeof authenticate;
  pf: (args: string[], input?: string) => Promise<string>;
  recordBlock: typeof recordBlock;
  recordUnblock: typeof recordUnblock;
  markReapplied: typeof markReapplied;
  getBlockHistory: typeof getBlockHistory;
  getBootId: typeof getBootId;
}

// The boundary makes privileged behavior testable without spawning sudo or modifying PF.
export function createFirewall(deps: FirewallDependencies) {
  let chain: Promise<unknown> = Promise.resolve();
  function serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = chain.then(operation, operation);
    chain = result.catch(() => undefined);
    return result;
  }
  const table = (operation: string, ip?: string) => deps.pf(['-a', ANCHOR, '-t', TABLE, '-T', operation, ...(ip ? [ip] : [])]);

  async function status(): Promise<FirewallStatus> {
    const errors: string[] = [];
    async function read<T>(name: string, fn: () => Promise<T>): Promise<T | null> {
      try { return await fn(); }
      catch (err) { errors.push(`${name}: ${errorMessage(err)}`); return null; }
    }
    const [pfEnabled, anchorLinked, rulesPresent, tableIPs] = await Promise.all([
      read('PF status', async () => {
        const info = await deps.pf(['-s', 'info']);
        if (!/^Status:\s*(Enabled|Disabled)\b/m.test(info)) throw new Error('Unrecognized status');
        return /^Status:\s*Enabled\b/m.test(info);
      }),
      read('Main rules', async () => /\banchor "(?:com\.apple\/\*|com\.apple\/250\.netwatcher)"/.test(await deps.pf(['-s', 'rules']))),
      read('Anchor rules', async () => {
        const rules = (await deps.pf(['-a', ANCHOR, '-s', 'rules'])).replace(/\s+/g, ' ');
        return rules.includes(`block drop out quick from any to <${TABLE}>`) && rules.includes(`block drop in quick from <${TABLE}> to any`);
      }),
      read('Table', async () => {
        try { return (await table('show')).split('\n').map(ip => ip.trim()).filter(Boolean).map(canonicalIP); }
        catch (err) {
          const e = err as { stderr?: string };
          if (/Table does not exist/i.test(`${e?.stderr ?? ''} ${errorMessage(err)}`)) return [];
          throw err;
        }
      }),
    ]);
    return { checkedAt: Date.now(), pfEnabled, anchorLinked, rulesPresent, tableIPs, errors, trafficVerified: false };
  }

  async function ensureAnchor(): Promise<void> {
    const before = await status();
    if (before.pfEnabled === null || before.anchorLinked === null || before.rulesPresent === null) {
      throw new Error('Cannot inspect firewall configuration');
    }
    if (!before.anchorLinked) throw new Error('Main PF rules do not reference the NetWatcher anchor');
    if (!before.pfEnabled) await deps.pf(['-e']);
    if (!before.rulesPresent) await deps.pf(['-a', ANCHOR, '-f', '-'], RULES);
    const after = await status();
    if (!after.pfEnabled || !after.anchorLinked || !after.rulesPresent || after.tableIPs === null) {
      throw new Error('Firewall configuration could not be verified after initialization');
    }
  }

  async function clearStates(ip: string): Promise<void> {
    // Single -k matches the source; two -k arguments also match the destination.
    // Execute BOTH even if the first fails, and report any incomplete cleanup.
    const errors: string[] = [];
    for (const args of [['-k', ip], ['-k', isIP(ip) === 6 ? '::/0' : '0.0.0.0/0', '-k', ip]]) {
      try { await deps.pf(args); } catch (err) { errors.push(errorMessage(err)); }
    }
    if (errors.length) throw new Error(errors.join('; '));
  }

  function credentialsError(password: string): string | null {
    return typeof password !== 'string' || !password || password.length > 1024 || /[\r\n\0]/.test(password)
      ? 'A valid single-line sudo password is required' : null;
  }

  async function mutate(ip: string, action: 'block' | 'unblock', reapply = false): Promise<ActionResult> {
    ip = canonicalIP(ip);
    const stages = { tableUpdated: false, stateCleanup: action === 'unblock' ? null as boolean | null : false, persisted: false };
    const errors: string[] = [];
    try {
      const alreadyAbsent = action === 'unblock' && (await status()).tableIPs?.includes(canonicalIP(ip)) === false;
      if (!alreadyAbsent) await table(action === 'block' ? 'add' : 'delete', ip);
      stages.tableUpdated = true;
    } catch (err) {
      return { success: false, message: `Firewall table update failed: ${errorMessage(err)}`, stages, trafficVerified: false };
    }
    // No network enrichment here: the operation cannot complete before its store write.
    try {
      if (action === 'unblock') await deps.recordUnblock(ip);
      else if (!reapply) await deps.recordBlock(ip, { country: null }, null);
      stages.persisted = true;
    } catch (err) { errors.push(`Table changed, but saved state could not be updated: ${errorMessage(err)}`); }
    if (action === 'block') {
      try { await clearStates(ip); stages.stateCleanup = true; }
      catch (err) { errors.push(`Rule added; existing-session cleanup incomplete: ${errorMessage(err)}`); }
    }
    const health = await status();
    const member = health.tableIPs?.includes(canonicalIP(ip));
    if (member === undefined || member !== (action === 'block') || (action === 'block' && (!health.pfEnabled || !health.anchorLinked || !health.rulesPresent))) {
      errors.push('Firewall configuration/table readback did not confirm the requested state');
    }
    if (action === 'block' && stages.persisted && errors.length === 0) {
      try {
        const boot = await deps.getBootId();
        if (boot !== null) await deps.markReapplied([ip], boot);
      } catch (err) { stages.persisted = false; errors.push(`Could not save application status: ${errorMessage(err)}`); }
    }
    return { success: errors.length === 0, partial: errors.length > 0, stages, trafficVerified: false,
      message: errors.join('; ') || `${action === 'block' ? 'Rule added and state cleanup completed' : 'Rule removed'} for ${ip}. Configuration checked; traffic blocking has not been independently tested.` };
  }

  function change(ip: string, password: string, action: 'block' | 'unblock'): Promise<ActionResult> {
    if (!isBlockableIP(ip)) return Promise.resolve({ success: false, message: 'Invalid or non-blockable IP address' });
    const invalid = credentialsError(password);
    if (invalid) return Promise.resolve({ success: false, message: invalid });
    return serialize(async () => {
      try {
        await deps.authenticate(password);
        if (action === 'block') await ensureAnchor();
        return await mutate(ip, action);
      } catch (err) { return { success: false, message: errorMessage(err) }; }
      finally { password = ''; }
    });
  }

  function reapply(password: string) {
    return serialize(async () => {
      const applied: string[] = [], failed: { ip: string; message: string }[] = [];
      try {
        const invalid = credentialsError(password);
        if (invalid) throw new Error(invalid);
        await deps.authenticate(password);
        // Read desired rules INSIDE the same queue as block/unblock, never before it.
        const ips = (await deps.getBlockHistory()).active.map(rec => rec.ip);
        if (ips.length) await ensureAnchor();
        for (const ip of ips) {
          const result = isBlockableIP(ip) ? await mutate(ip, 'block', true) : { success: false, message: 'Non-blockable IP' };
          if (result.success) applied.push(ip);
          else failed.push({ ip, message: result.message });
        }
        return { success: failed.length === 0, applied, failed, message: `${applied.length} rules reapplied; ${failed.length} failed. Traffic blocking has not been independently tested.` };
      } catch (err) { return { success: false, applied, failed, message: errorMessage(err) }; }
      finally { password = ''; }
    });
  }
  return { blockIP: (ip: string, password: string) => change(ip, password, 'block'),
    unblockIP: (ip: string, password: string) => change(ip, password, 'unblock'), reapplyBlocks: reapply, getFirewallStatus: status };
}

const firewall = createFirewall({ authenticate, recordBlock, recordUnblock, markReapplied, getBlockHistory, getBootId,
  pf: async (args, input) => {
    if (input !== undefined) { await sudoInput(['-n', '/sbin/pfctl', ...args], input); return ''; }
    return (await execFileAsync('/usr/bin/sudo', ['-n', '/sbin/pfctl', ...args], { timeout: 5000, maxBuffer: 1024 * 1024 })).stdout;
  },
});
export const { blockIP, unblockIP, reapplyBlocks, getFirewallStatus } = firewall;
export async function getBlockedIPsOrNull(): Promise<string[] | null> {
  return (await getFirewallStatus()).tableIPs;
}
