import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getConnections, parseConnections } from './connections.js';

test('file-descriptor parsing preserves state after the name and separates IPv6 / UDP sockets', () => {
  const data = 'p42\ncBrowser\nf7\nPTCP\nn192.168.1.1:1234->203.0.113.1:443\nTST=ESTABLISHED\nf8\nPUDP\nn[::1]:1235->[2001:db8::1]:443\nf9\nPTCP\nn*:80\nTST=LISTEN\n';
  const result = parseConnections(data);
  assert.equal(result.length, 2); assert.equal(result[0].state, 'ESTABLISHED');
  assert.equal(result[1].protocol, 'UDP'); assert.equal(result[1].remoteAddress, '2001:db8::1');
  assert.equal(result[1].state, 'UNKNOWN');
});

test('only an empty lsof selection is empty; timeouts, permissions and partial failures propagate', async () => {
  const failing = (error: object) => (async () => { throw error; }) as Parameters<typeof getConnections>[0];
  assert.deepEqual(await getConnections(failing({ code: 1, stdout: '', stderr: '' })), []);
  for (const error of [{ code: 'ENOENT' }, { code: 1, stderr: 'permission denied' }, { code: 1, stdout: 'p42' }, { code: 1, killed: true }]) {
    await assert.rejects(getConnections(failing(error)), /collector unavailable/);
  }
});
