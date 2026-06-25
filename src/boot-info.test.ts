import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseBootSec } from './boot-info.js';

test('parseBootSec extracts the epoch second from kern.boottime output', () => {
  assert.equal(parseBootSec('{ sec = 1719300000, usec = 0 } Tue Jun 25 10:00:00 2026'), 1719300000);
});

test('parseBootSec tolerates no spaces around the equals sign', () => {
  assert.equal(parseBootSec('{ sec=1719300123, usec=5 }'), 1719300123);
});

test('parseBootSec returns null on malformed or empty input', () => {
  assert.equal(parseBootSec(''), null);
  assert.equal(parseBootSec('no numbers here'), null);
});
