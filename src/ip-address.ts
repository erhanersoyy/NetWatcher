import { isIP } from 'node:net';

// PF prints compressed, lowercase IPv6. Keep address families distinct.
export function canonicalIP(ip: string): string {
  return !ip.includes('%') && isIP(ip) === 6
    ? new URL(`http://[${ip}]/`).hostname.slice(1, -1)
    : ip;
}
