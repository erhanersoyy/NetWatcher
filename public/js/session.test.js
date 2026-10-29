import { test } from 'node:test';
import assert from 'node:assert/strict';
import { establishSession } from './session.js';

test('launch capability is removed before exchange; reload uses only the session cookie', async t => {
  const previousLocation = globalThis.location, previousHistory = globalThis.history;
  t.after(() => { globalThis.location = previousLocation; globalThis.history = previousHistory; });
  globalThis.location = { hash: '#access=test-launch-capability', pathname: '/', search: '' };
  globalThis.history = { replaceState: (_state, _unused, path) => { assert.equal(path, '/'); globalThis.location.hash = ''; } };
  const requests = [];
  const fetchMock = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(globalThis.location.hash, '', 'must clear fragment before making any request');
    requests.push({ url, options }); return { ok: true };
  });
  assert.equal(await establishSession(), true);
  assert.equal(requests[0].options.method, 'POST');
  assert.equal(requests[0].options.headers.Authorization, 'Bearer test-launch-capability');
  assert.equal(requests[0].url, '/api/session');
  assert.equal(await establishSession(), true);
  assert.equal(requests[1].options.method, 'GET');
  assert.equal(requests[1].options.headers.Authorization, undefined);
  fetchMock.mock.mockImplementation(async () => ({ ok: false }));
  assert.equal(await establishSession(), false);
});
