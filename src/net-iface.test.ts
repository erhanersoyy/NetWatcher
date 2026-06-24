import { test } from 'node:test';
import assert from 'node:assert/strict';
import type * as os from 'node:os';
import { pickPrimaryIPv4 } from './net-iface.js';

const v4 = (address: string, internal = false): os.NetworkInterfaceInfo =>
  ({ address, family: 'IPv4', internal, netmask: '', mac: '', cidr: null });

test('prefers en0 over VPN/Docker interfaces regardless of enumeration order', () => {
  const nets = {
    lo0: [v4('127.0.0.1', true)],
    en0: [v4('192.168.1.20')],
    utun3: [v4('10.8.0.2')],
    bridge100: [v4('192.168.64.1')],
  };
  assert.equal(pickPrimaryIPv4(nets), '192.168.1.20');
});

test('falls back to any external IPv4 when no en* exists', () => {
  const nets = { eth0: [v4('172.16.0.5')] };
  assert.equal(pickPrimaryIPv4(nets), '172.16.0.5');
});

test('skips virtual interfaces and falls back to loopback when nothing else', () => {
  const nets = { lo0: [v4('127.0.0.1', true)], utun0: [v4('10.0.0.1')], bridge0: [v4('192.168.64.1')] };
  assert.equal(pickPrimaryIPv4(nets), '127.0.0.1');
});

test('skips APIPA/link-local (169.254.x.x) and picks the real LAN IP', () => {
  const nets = {
    en5: [v4('169.254.10.20')], // disconnected adapter, self-assigned APIPA
    en0: [v4('192.168.1.20')],
  };
  assert.equal(pickPrimaryIPv4(nets), '192.168.1.20');
});
