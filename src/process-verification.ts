import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { open, realpath, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { promisify } from 'node:util';
import type { ProcessIdentity } from './process-identity.js';

export interface ProcessVerification {
  state: 'queued' | 'checking' | 'complete' | 'unavailable';
  signature: 'valid' | 'ad-hoc' | 'unsigned' | 'invalid' | 'unavailable';
  seal: 'verified' | 'failed' | 'unavailable';
  signer: string | null;
  teamId: string | null;
  sha256: string | null;
  hashChanged: boolean;
  checkedAt: number | null;
  detail: string | null;
}

interface FileSnapshot { path: string; key: string; size: bigint }
interface CommandResult { ok: boolean; stderr: string; interrupted?: boolean }
interface Dependencies {
  snapshot: (path: string) => Promise<FileSnapshot>;
  command: (args: string[], signal: AbortSignal) => Promise<CommandResult>;
  hash: (file: FileSnapshot, signal: AbortSignal) => Promise<string>;
  now: () => number;
}

const execFileAsync = promisify(execFile);
const MAX_HASH_BYTES = 512n * 1024n * 1024n;
const CACHE_MS = 5 * 60_000;
const RETRY_MS = 60_000;
const MAX_ENTRIES = 256;
const MAX_QUEUE = 128;

function fingerprint(s: BigIntStats): string {
  return [s.dev, s.ino, s.size, s.mtimeNs, s.ctimeNs, s.mode].join(':');
}

async function snapshot(path: string): Promise<FileSnapshot> {
  const resolved = await realpath(path);
  const s = await stat(resolved, { bigint: true });
  if (!s.isFile()) throw new Error('Not a regular file');
  return { path: resolved, key: fingerprint(s), size: s.size };
}

const defaults: Dependencies = {
  snapshot,
  now: Date.now,
  async command(args, signal) {
    try {
      const { stderr } = await execFileAsync('/usr/bin/codesign', args, {
        timeout: 8000, maxBuffer: 128 * 1024, signal,
        env: { ...process.env, LC_ALL: 'C' },
      });
      return { ok: true, stderr };
    } catch (error) {
      const e = error as { stderr?: string; killed?: boolean; code?: number | string };
      return { ok: false, stderr: e.stderr || '', interrupted: e.killed || typeof e.code !== 'number' };
    }
  },
  async hash(file, signal) {
    // O_NONBLOCK prevents a replacement FIFO from hanging open(); O_NOFOLLOW
    // rejects a final-component symlink introduced after realpath().
    const handle = await open(file.path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    try {
      const s = await handle.stat({ bigint: true });
      if (!s.isFile() || fingerprint(s) !== file.key) throw new Error('File changed');
      const hash = createHash('sha256');
      let bytes = 0n;
      for await (const chunk of handle.createReadStream({ autoClose: false, signal })) {
        bytes += BigInt(chunk.length);
        if (bytes > MAX_HASH_BYTES) throw new Error('File grew beyond hash limit');
        hash.update(chunk);
      }
      if (fingerprint(await handle.stat({ bigint: true })) !== file.key) throw new Error('File changed');
      return hash.digest('hex');
    } finally { await handle.close(); }
  },
};

function empty(state: ProcessVerification['state'], detail: string | null = null): ProcessVerification {
  return { state, signature: 'unavailable', seal: 'unavailable', signer: null,
    teamId: null, sha256: null, hashChanged: false, checkedAt: null, detail };
}

function signatureResult(verify: CommandResult, display: CommandResult): Pick<ProcessVerification, 'signature' | 'seal' | 'signer' | 'teamId' | 'detail'> {
  const base = { signature: 'unavailable' as const, seal: 'unavailable' as const, signer: null, teamId: null, detail: null };
  if (verify.interrupted) return { ...base, detail: 'Signature check timed out or could not run.' };
  if (verify.ok) {
    if (!display.ok) return { ...base, seal: 'verified', detail: 'Signature metadata unavailable.' };
    const adhoc = /^Signature=adhoc\s*$/m.test(display.stderr) || /^CodeDirectory .*flags=.*\badhoc\b/m.test(display.stderr);
    const authority = display.stderr.match(/^Authority=(.+)$/m)?.[1]?.trim();
    const team = display.stderr.match(/^TeamIdentifier=(.+)$/m)?.[1]?.trim();
    return { signature: adhoc ? 'ad-hoc' : 'valid', seal: 'verified',
      signer: !adhoc && authority && authority !== '(unavailable)' ? authority : null,
      teamId: !adhoc && team && team !== 'not set' ? team : null, detail: null };
  }
  if (/: code object is not signed at all\s*$/m.test(verify.stderr)) return { ...base, signature: 'unsigned' };
  if (/: (?:code or signature modified|invalid signature[^\n]*|a sealed resource is missing or invalid|file added|file modified|file missing)\s*$/m.test(verify.stderr)) {
    return { ...base, signature: 'invalid', seal: 'failed', detail: 'Code signature verification failed.' };
  }
  // Trust-service, permissions, unsupported format and policy errors are not
  // evidence of file tampering. Never expose raw tool diagnostics as UI HTML.
  return { ...base, detail: 'Signature could not be verified in this environment.' };
}

interface Entry {
  file: FileSnapshot;
  sourcePath: string;
  result: ProcessVerification;
  baseline: string | null;
  seenAt: number;
  controller: AbortController;
}

/** Read-only, bounded, in-memory verification of OS-reported executable files.
 * Disk evidence only: no runtime-image, interpreter-script or whole-app claim.
 */
export function createProcessVerifier(overrides: Partial<Dependencies> = {}) {
  const deps = { ...defaults, ...overrides };
  const entries = new Map<string, Entry>();
  const queue: Entry[] = [];
  let running = 0;
  let stopped = false;

  async function run(entry: Entry): Promise<void> {
    const { file, controller } = entry;
    const deadline = setTimeout(() => controller.abort(), 20_000);
    const current = () => entries.get(file.path) === entry && !stopped;
    try {
      const before = await deps.snapshot(entry.sourcePath);
      if (before.path !== file.path || before.key !== file.key) throw new Error('File changed');
      controller.signal.throwIfAborted();
      const verify = await deps.command(['--verify', '--strict', '--verbose=2', file.path], controller.signal);
      controller.signal.throwIfAborted();
      const display = verify.ok
        ? await deps.command(['--display', '--verbose=4', file.path], controller.signal)
        : { ok: false, stderr: '' };
      controller.signal.throwIfAborted();
      let sha256: string | null = null;
      let hashDetail: string | null = null;
      if (file.size > MAX_HASH_BYTES) hashDetail = 'SHA-256 skipped: executable exceeds 512 MiB.';
      else {
        try { sha256 = await deps.hash(file, controller.signal); }
        catch { hashDetail = 'SHA-256 unavailable.'; }
      }
      const after = await deps.snapshot(entry.sourcePath);
      if (after.path !== file.path || after.key !== file.key) throw new Error('File changed');
      if (!current()) return;
      const signature = signatureResult(verify, display);
      entry.result = { ...empty('complete'), ...signature, sha256,
        hashChanged: Boolean(sha256 && entry.baseline && sha256 !== entry.baseline),
        checkedAt: deps.now(), detail: [signature.detail, hashDetail].filter(Boolean).join(' ') || null };
      entry.baseline ??= sha256;
    } catch {
      if (current()) entry.result = { ...empty('unavailable', controller.signal.aborted
        ? 'Verification timed out or was cancelled.'
        : 'File changed or became unreadable during verification.'), checkedAt: deps.now() };
    } finally {
      clearTimeout(deadline);
      running--;
      pump();
    }
  }

  function pump(): void {
    while (!stopped && running < 2 && queue.length) {
      const entry = queue.shift()!;
      if (entries.get(entry.file.path) !== entry || entry.controller.signal.aborted) continue;
      running++;
      entry.result = empty('checking');
      void run(entry);
    }
  }

  return {
    async inspect(identity: ProcessIdentity | null): Promise<ProcessVerification> {
      if (stopped || !identity || !isAbsolute(identity.executable)) return empty('unavailable', 'Executable identity unavailable.');
      let file: FileSnapshot;
      try { file = await deps.snapshot(identity.executable); }
      catch { return empty('unavailable', 'Executable is missing, unreadable or not a regular file.'); }
      if (stopped) return empty('unavailable');
      const cached = entries.get(file.path);
      const now = deps.now();
      if (cached) {
        cached.seenAt = now;
        const ttl = cached.result.signature === 'unavailable' || !cached.result.sha256 ? RETRY_MS : CACHE_MS;
        if (cached.file.key === file.key && (cached.result.checkedAt === null || now - cached.result.checkedAt < ttl)) return cached.result;
        cached.controller.abort();
      }
      if (queue.length >= MAX_QUEUE) return empty('queued', 'Waiting for verification capacity.');
      if (!cached && entries.size >= MAX_ENTRIES) {
        const oldest = [...entries.values()].filter(e => e.result.checkedAt !== null).sort((a, b) => a.seenAt - b.seenAt)[0];
        if (!oldest) return empty('queued', 'Waiting for verification capacity.');
        entries.delete(oldest.file.path);
      }
      const entry: Entry = { file, sourcePath: identity.executable, result: empty('queued'),
        baseline: cached?.baseline ?? null, seenAt: now, controller: new AbortController() };
      entries.set(file.path, entry);
      queue.push(entry);
      pump();
      return entry.result;
    },
    shutdown(): void {
      stopped = true;
      for (const entry of entries.values()) entry.controller.abort();
      queue.length = 0;
      entries.clear();
    },
  };
}

export const processVerifier = createProcessVerifier();
