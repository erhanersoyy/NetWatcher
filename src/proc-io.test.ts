import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { safeEndStdin } from './proc-io.js';

test('safeEndStdin does not throw when the child stdin is already destroyed', async () => {
  // `cat` exits immediately on a closed stdin; kill it to force the pipe shut,
  // reproducing the EPIPE/ERR_STREAM_DESTROYED that crashed the server.
  const child = spawn('cat');
  child.stdin.destroy();
  child.kill('SIGKILL');
  await new Promise((r) => child.on('close', r));
  assert.doesNotThrow(() => safeEndStdin(child, 'data\n'));
});

test('safeEndStdin writes to a healthy child without throwing', async () => {
  const child = spawn('cat');
  assert.doesNotThrow(() => safeEndStdin(child, 'hello\n'));
  await new Promise((r) => child.on('close', r));
});
