import type * as os from 'node:os';

// Virtual / tunnel interfaces that should never be reported as the host's
// primary LAN address: VPN tunnels (utun), bridges (Docker/VMs), and Apple's
// link-local helper interfaces (llw, awdl).
const VIRTUAL_PREFIXES = ['utun', 'bridge', 'llw', 'awdl', 'ipsec', 'gif', 'stf'];

function isVirtual(name: string): boolean {
  return VIRTUAL_PREFIXES.some((p) => name.startsWith(p));
}

/**
 * Pick the host's primary external IPv4. Prefers physical `en*` interfaces
 * (Wi-Fi/Ethernet on macOS), then any other non-virtual external IPv4, and
 * finally falls back to loopback. Deterministic regardless of the order
 * `networkInterfaces()` returns interfaces in.
 */
export function pickPrimaryIPv4(nets: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string {
  let preferred: string | null = null; // en*
  let fallback: string | null = null;  // any other non-virtual external

  for (const name of Object.keys(nets)) {
    if (isVirtual(name)) continue;
    for (const net of nets[name] ?? []) {
      if (net.family !== 'IPv4' || net.internal) continue;
      // Skip APIPA/link-local self-assigned addresses (169.254.0.0/16) — a
      // disconnected adapter can carry one and it is not a real LAN address.
      if (net.address.startsWith('169.254.')) continue;
      if (name.startsWith('en')) {
        if (!preferred) preferred = net.address;
      } else if (!fallback) {
        fallback = net.address;
      }
    }
  }
  return preferred ?? fallback ?? '127.0.0.1';
}
