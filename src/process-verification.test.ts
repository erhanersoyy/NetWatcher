import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, symlink, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { createProcessVerifier } from './process-verification.js';

const identity = (executable = '/example', pid = 42) => ({ executable, pid, parentPid: 1, uid: 501, startedAt: 'today', token: 'a'.repeat(64) });
const snapshot = async (path: string) => ({ path, key: 'v1', size: 10n });
const signed = { ok: true, stderr: 'Authority=Developer ID Application: Example\nTeamIdentifier=TEAM123\n' };
const hash = async () => 'a'.repeat(64);
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>(r => { resolve = r; });
  return { promise, resolve };
};
async function finished(verifier: ReturnType<typeof createProcessVerifier>, path = '/example') {
  for (let i = 0; i < 500; i++) {
    const result = await verifier.inspect(identity(path));
    if (result.checkedAt !== null) return result;
    await setImmediate();
  }
  assert.fail('Verification did not finish');
}

test('inspection does not await codesign; PIDs sharing a file share one cached check', async t => {
  const gate = deferred();
  let calls = 0;
  const verifier = createProcessVerifier({ snapshot, hash, command: async args => {
    calls++; assert.equal(args.at(-1), '/example');
    await gate.promise; return signed;
  } });
  t.after(() => { gate.resolve(); verifier.shutdown(); });
  assert.equal((await verifier.inspect(identity())).state, 'checking');
  assert.equal((await verifier.inspect(identity('/example', 43))).state, 'checking');
  assert.equal(calls, 1);
  gate.resolve();
  const result = await finished(verifier);
  assert.equal(result.signature, 'valid'); assert.equal(result.seal, 'verified');
  assert.equal(result.signer, 'Developer ID Application: Example'); assert.equal(result.teamId, 'TEAM123');
  assert.equal(result.sha256, 'a'.repeat(64)); assert.equal(result.hashChanged, false);
  await verifier.inspect(identity());
  assert.equal(calls, 2); // one verify + one metadata command, no new process
});

test('signature outcomes distinguish unsigned/ad-hoc/tampering from unavailable trust services', async t => {
  const cases = [
    { verify: { ok: false, stderr: '/example: code object is not signed at all\n' }, display: signed, signature: 'unsigned', seal: 'unavailable' },
    { verify: { ok: true, stderr: '' }, display: { ok: true, stderr: 'Signature=adhoc\nTeamIdentifier=not set\n' }, signature: 'ad-hoc', seal: 'verified' },
    { verify: { ok: true, stderr: '' }, display: { ok: true, stderr: 'Authority=(unavailable)\nTeamIdentifier=not set\n' }, signature: 'valid', seal: 'verified' },
    { verify: { ok: false, stderr: '/example: code or signature modified\n' }, display: signed, signature: 'invalid', seal: 'failed' },
    { verify: { ok: false, stderr: '/example: CSSMERR_TP_NOT_TRUSTED\n' }, display: signed, signature: 'unavailable', seal: 'unavailable' },
    { verify: { ok: false, stderr: '/example: code or signature modified\n', interrupted: true }, display: signed, signature: 'unavailable', seal: 'unavailable' },
    { verify: { ok: true, stderr: '' }, display: { ok: false, stderr: 'Permission denied' }, signature: 'unavailable', seal: 'verified' },
  ];
  for (const c of cases) {
    await t.test(`${c.signature}/${c.seal}: ${c.verify.stderr || c.display.stderr}`, async () => {
      const verifier = createProcessVerifier({ snapshot, hash, command: async args => args[0] === '--verify' ? c.verify : c.display });
      try {
        const result = await finished(verifier);
        assert.equal(result.signature, c.signature); assert.equal(result.seal, c.seal);
        if (c.signature !== 'valid') assert.equal(result.signer, null);
      } finally { verifier.shutdown(); }
    });
  }
});

test('metadata change invalidates cache, hash changes stay visible, TTL rechecks unchanged files', async t => {
  let key = 'v1', digest = 'a'.repeat(64), now = 1000, checks = 0;
  const verifier = createProcessVerifier({ snapshot: async path => ({ path, key, size: 10n }),
    hash: async () => digest, now: () => now, command: async args => { if (args[0] === '--verify') checks++; return signed; } });
  t.after(() => verifier.shutdown());
  await finished(verifier);
  key = 'v2'; digest = 'b'.repeat(64);
  assert.equal((await verifier.inspect(identity())).signature, 'unavailable');
  assert.equal((await finished(verifier)).hashChanged, true);
  now += 5 * 60_000;
  assert.equal((await verifier.inspect(identity())).state, 'checking');
  assert.equal((await finished(verifier)).hashChanged, true);
  assert.equal(checks, 3);
});

test('only two jobs run concurrently and queue overflow returns a retryable queued state', async t => {
  const gate = deferred();
  let active = 0, peak = 0;
  const verifier = createProcessVerifier({ snapshot, hash, command: async () => {
    active++; peak = Math.max(peak, active); await gate.promise; active--; return signed;
  } });
  t.after(() => { gate.resolve(); verifier.shutdown(); });
  const initial = await Promise.all(Array.from({ length: 140 }, (_, i) => verifier.inspect(identity(`/example-${i}`))));
  assert.equal(initial.filter(r => r.state === 'checking').length, 2);
  assert.equal(initial.filter(r => r.detail?.includes('capacity')).length, 10);
  gate.resolve();
  await finished(verifier, '/example-139');
  assert.equal(peak, 2);
});

test('late result for a replaced file cannot overwrite the newer verification', async t => {
  const gate = deferred();
  let key = 'old', first = true;
  const verifier = createProcessVerifier({ snapshot: async path => ({ path, key, size: 10n }), hash,
    command: async () => { if (first) { first = false; await gate.promise; } return signed; } });
  t.after(() => { gate.resolve(); verifier.shutdown(); });
  await verifier.inspect(identity());
  await setImmediate();
  key = 'new';
  const result = await finished(verifier);
  assert.equal(result.signature, 'valid');
  gate.resolve(); await setImmediate();
  assert.deepEqual(await verifier.inspect(identity()), result);
});

test('a file replaced during a check is never reported as verified', async t => {
  let key = 'old';
  const verifier = createProcessVerifier({ snapshot: async path => ({ path, key, size: 10n }), hash,
    command: async () => { key = 'replaced'; return signed; } });
  t.after(() => verifier.shutdown());
  await verifier.inspect(identity());
  await setImmediate();
  // Restore metadata only in this fake snapshot so we can inspect the failed
  // result itself instead of immediately scheduling the next file version.
  key = 'old';
  const result = await verifier.inspect(identity());
  assert.equal(result.state, 'unavailable'); assert.equal(result.seal, 'unavailable');
});

test('real file hashing, symlink deduplication and replacements; directories are rejected', async t => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'netwatcher-verify-')));
  const path = join(dir, 'example with spaces; $(ignored)');
  const alias = join(dir, 'alias');
  let calls = 0;
  const verifier = createProcessVerifier({ command: async args => {
    calls++; assert.equal(args.at(-1), path);
    return { ok: false, stderr: `${path}: code object is not signed at all\n` };
  } });
  t.after(async () => { verifier.shutdown(); await rm(dir, { recursive: true, force: true }); });
  await writeFile(path, 'first'); await symlink(path, alias);
  const first = await finished(verifier, path);
  assert.equal(first.sha256, createHash('sha256').update('first').digest('hex'));
  assert.equal((await verifier.inspect(identity(alias))).sha256, first.sha256);
  assert.equal(calls, 1);
  await writeFile(path, 'second version');
  const second = await finished(verifier, path);
  assert.equal(second.hashChanged, true); assert.notEqual(second.sha256, first.sha256);
  assert.equal((await verifier.inspect(identity(dir))).state, 'unavailable');
  assert.equal((await verifier.inspect(identity(join(dir, 'missing')))).state, 'unavailable');
});

test('missing identities and oversized hashes do not execute targets or imply verified integrity', async t => {
  let calls = 0;
  const verifier = createProcessVerifier({ snapshot: async path => ({ path, key: 'v1', size: 513n * 1024n * 1024n }),
    command: async () => { calls++; return { ok: false, stderr: '/example: code object is not signed at all\n' }; },
    hash: async () => { assert.fail('Oversized file must not be hashed'); } });
  t.after(() => verifier.shutdown());
  assert.equal((await verifier.inspect(null)).state, 'unavailable');
  assert.equal((await verifier.inspect(identity('relative'))).state, 'unavailable');
  assert.equal(calls, 0);
  const result = await finished(verifier);
  assert.equal(result.sha256, null); assert.equal(result.seal, 'unavailable');
  assert.match(result.detail!, /512 MiB/);
});

test('shutdown aborts running commands and does not start queued work', async () => {
  let calls = 0, aborted = 0;
  const verifier = createProcessVerifier({ snapshot, hash, command: async (_args, signal) => {
    calls++;
    await new Promise<void>(resolve => signal.addEventListener('abort', () => { aborted++; resolve(); }, { once: true }));
    return { ok: false, stderr: '', interrupted: true };
  } });
  await Promise.all(['/one', '/two', '/three'].map(p => verifier.inspect(identity(p))));
  await setImmediate(); verifier.shutdown(); await setImmediate();
  assert.equal(calls, 2); assert.equal(aborted, 2);
  assert.equal((await verifier.inspect(identity())).state, 'unavailable');
});
