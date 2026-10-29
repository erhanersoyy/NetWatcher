import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Router } from 'express';
import { request, type Server } from 'node:http';
import { gzipSync } from 'node:zlib';
import { createApp } from './app.js';

const ACCESS = 'test-only-access-key-'.repeat(3);
const HEADERS = { Host: '127.0.0.1:3847', 'x-requested-by': 'netwatcher' };
function send(server: Server, path: string, method = 'GET', headers: Record<string, string> = {}, body = '') {
  return new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Test server missing');
    const req = request({ host: '127.0.0.1', port: address.port, path, method, headers: { ...HEADERS, ...headers } }, res => {
      let data = ''; res.setEncoding('utf8'); res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: data }));
    });
    req.on('error', reject); req.end(body);
  });
}

test('local HTTP boundary: session, SSE, CSRF, early guards, parser limits and response headers', async t => {
  const router = Router();
  let mutations = 0;
  router.get('/api/private', (_req, res) => res.json({ private: true }));
  router.get('/api/traffic-stream', (_req, res) => res.send('test stream'));
  router.post('/api/mutate', (_req, res) => { mutations++; res.json({ success: true }); });
  const server = createApp(ACCESS, router).listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  t.after(() => { server.closeAllConnections(); server.close(); });
  assert.equal((await send(server, '/api/private')).status, 401, 'a forged static header cannot authorize a local client');
  assert.equal((await send(server, '/api/traffic-stream', 'GET', { 'x-requested-by': '' })).status, 401);
  assert.equal((await send(server, '/api/session', 'POST', { Authorization: 'Bearer wrong' })).status, 401);
  assert.equal((await send(server, '/api/session', 'POST', { Authorization: `Bearer ${ACCESS}`, Origin: 'http://evil.test' })).status, 403);
  const login = await send(server, '/api/session', 'POST', { Authorization: `Bearer ${ACCESS}` });
  assert.equal(login.status, 200);
  const setCookie = login.headers['set-cookie']![0];
  assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /SameSite=Strict/); assert.match(setCookie, /Path=\/api/);
  assert.equal(setCookie.includes(ACCESS), false);
  const Cookie = setCookie.split(';')[0];
  assert.equal((await send(server, '/api/private', 'GET', { Cookie })).status, 200);
  assert.equal((await send(server, '/api/traffic-stream', 'GET', { Cookie, 'x-requested-by': '' })).status, 200);
  assert.equal((await send(server, '/api/mutate', 'POST', { Cookie, 'x-requested-by': '' })).status, 403);
  assert.equal((await send(server, '/api/mutate', 'POST', { Cookie, Origin: 'http://localhost:3847' })).status, 403, 'origin must match this host exactly');
  assert.equal((await send(server, '/api/private', 'GET', { Cookie, 'sec-fetch-site': 'cross-site' })).status, 403);
  const malformed = '{"password":"DO_NOT_ECHO"';
  for (const [headers, expected] of [[{ Host: 'evil.test' }, 403], [{ Origin: 'https://evil.test' }, 403], [{ Cookie: '' }, 401]] as const) {
    assert.equal((await send(server, '/api/mutate', 'POST', { Cookie, 'Content-Type': 'application/json', ...headers }, malformed)).status, expected);
  }
  const bad = await send(server, '/api/mutate', 'POST', { Cookie, 'Content-Type': 'application/json' }, malformed);
  assert.equal(bad.status, 400); assert.equal(bad.body.includes('DO_NOT_ECHO'), false);
  assert.equal((await send(server, '/api/mutate', 'POST', { Cookie, 'Content-Type': 'application/json' }, JSON.stringify({ x: 'a'.repeat(9000) }))).status, 413);
  // Encoded data never reaches decompression, including malformed trailing bytes.
  const compressed = gzipSync('{}').toString('base64') + 'trailing';
  assert.equal((await send(server, '/api/mutate', 'POST', { Cookie, 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, compressed)).status, 415);
  assert.equal(mutations, 0);
  assert.equal((await send(server, '/api/mutate', 'POST', { Cookie, 'Content-Type': 'application/json' }, '{}')).status, 200);
  assert.equal(mutations, 1);
  const page = await send(server, '/');
  assert.equal(page.status, 200);
  assert.match(String(page.headers['content-security-policy']), /frame-ancestors 'none'/);
  assert.equal(page.headers['x-frame-options'], 'DENY');
  assert.equal(page.headers['x-content-type-options'], 'nosniff');
  assert.equal(page.headers['referrer-policy'], 'no-referrer');
  assert.equal(page.body.includes(ACCESS), false);
  assert.equal(page.body.includes('https://unpkg.com'), false);
  assert.equal(page.body.includes('fonts.googleapis.com'), false);
  assert.equal((await send(server, '/', 'GET', { Host: 'evil.test' })).status, 403);
});
