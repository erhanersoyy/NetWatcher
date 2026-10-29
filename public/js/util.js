// ---------- Pure helpers (no DOM / no module state) ----------

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export function escapeHtml(str) {
  // Regex replace is ~10× faster than creating a <div> per call. Only
  // matters in hot render paths (renderConnBlock runs for every visible
  // conn × 6–8 escapeHtml calls per render).
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

export function isIPv6(addr) { return typeof addr === 'string' && addr.includes(':'); }

export function canonicalIP(ip) {
  if (typeof ip !== 'string' || !ip.includes(':') || ip.includes('%')) return ip;
  try { return new URL(`http://[${ip}]/`).hostname.slice(1, -1); }
  catch { return ip; }
}

export function isLocalhost(addr) { return addr === '127.0.0.1' || addr === '::1' || (typeof addr === 'string' && addr.startsWith('127.')); }

export function isPrivateIP(addr) {
  if (!addr) return false;
  if (addr.startsWith('10.') || addr.startsWith('192.168.') || addr.startsWith('127.')) return true;
  if (addr === '0.0.0.0' || addr === '::' || addr === '::1' || addr.startsWith('169.254.') || addr.startsWith('fe80:')) return true;
  const lower = addr.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.slice(7);
    if (v4.includes('.')) return isPrivateIP(v4);
  }
  if (addr.startsWith('172.')) {
    const s = parseInt(addr.split('.')[1], 10);
    if (s >= 16 && s <= 31) return true;
  }
  if (addr.startsWith('100.')) {
    const s = parseInt(addr.split('.')[1], 10);
    if (s >= 64 && s <= 127) return true;
  }
  if (/^f[cd][0-9a-f]{2}:/i.test(addr)) return true;
  return false;
}

export function flag(code) {
  if (!code || code === 'LO' || code === '??') return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

export function formatBytes(n) {
  if (n === undefined || n === null || isNaN(n)) return '-';
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function fmtBytes(n) {
  if (n == null) return '—';
  const gb = n / (1024 ** 3);
  return gb >= 1 ? gb.toFixed(1) + ' GB' : (n / (1024 ** 2)).toFixed(0) + ' MB';
}

export function relTime(ts) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

export function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function looksLikeIP(s) {
  if (typeof s !== 'string') return false;
  const v = s.trim();
  if (v.length === 0 || v.length > 45) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return v.split('.').every(o => Number(o) <= 255);
  if (v.includes(':') && /^[0-9a-fA-F:.]+$/.test(v)) {
    try { return new URL(`http://[${v}]/`).hostname.length > 0; } catch { return false; }
  }
  return false;
}

// A readable pf table proves membership, not packet-filter enforcement.
export function describeBlock(ip, pfIPs, savedIPs, staleCount = 0, historyFresh = true, health = null) {
  ip = canonicalIP(ip);
  if (pfIPs?.has(ip)) {
    if (health?.pfEnabled === false) return { kind: 'pending', label: 'In table · PF disabled' };
    if (health?.anchorLinked === false || health?.rulesPresent === false) return { kind: 'pending', label: 'In table · rules incomplete' };
    if (health && (health.pfEnabled !== true || health.anchorLinked !== true || health.rulesPresent !== true)) return { kind: 'unknown', label: 'In table · PF unverified' };
    return { kind: 'present', label: 'In firewall table' };
  }
  if (pfIPs && savedIPs.has(ip)) return { kind: 'pending', label: 'Not in firewall table' };
  return { kind: 'unknown', label: savedIPs.has(ip) ? 'Saved · unverified' : 'Status unavailable' };
}

export function blockRepairStatus(pfIPs, savedIPs, health) {
  if (!savedIPs.size) return null;
  if (health?.pfEnabled === false || health?.rulesPresent === false || health?.anchorLinked === false) {
    return { urgent: true, message: 'Saved rules need attention: firewall configuration is incomplete.' };
  }
  if (pfIPs) {
    const missing = [...savedIPs.keys()].filter(ip => !pfIPs.has(canonicalIP(ip))).length;
    if (missing) return { urgent: true, message: `${missing} saved rules are missing from the firewall table.` };
    if (health?.pfEnabled === true && health?.rulesPresent === true && health?.anchorLinked === true) return null;
  }
  return { urgent: false, message: 'Saved rules could not be verified. Check status before re-applying.' };
}

export function summarizeProcesses(processes) {
  const countries = new Set(), providers = new Set();
  let connections = 0, system = 0, established = 0, timewait = 0, other = 0;
  for (const p of processes) {
    if (p.isSystemProcess) system++;
    for (const c of p.connections) {
      connections++;
      if (c.geo?.countryCode && c.geo.countryCode !== 'LO') countries.add(c.geo.countryCode);
      if (c.geo?.isp) providers.add(c.geo.isp);
      const state = (c.state || '').toUpperCase();
      if (state.startsWith('EST')) established++;
      else if (state.includes('TIME')) timewait++;
      else other++;
    }
  }
  return { processes: processes.length, system, user: processes.length - system,
    connections, countries: countries.size, providers: providers.size, established, timewait, other };
}

export function sampleRate(previous, current, seconds) {
  if (previous == null || seconds <= 0) return 0;
  return Math.max(0, current < previous ? current : current - previous) / seconds;
}

export function csvCell(value) {
  const text = String(value ?? '');
  // Avoid spreadsheet formula execution when exporting third-party metadata.
  const safe = /^[=+@\-\t\r]/.test(text) ? "'" + text : text;
  return '"' + safe.replaceAll('"', '""') + '"';
}
