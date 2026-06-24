/* ============================================================
   NetWatcher — modal dialogs, focus-trap, toast, blocked sidebar
   ============================================================ */

import { escapeHtml, flag, relTime } from './util.js';
import { el } from './dom.js';
import { S, on } from './state.js';

// ---------- Toast ----------
export function showToast(message, type) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `toast ${type || ''}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// Minimal modal focus management: save the previously-focused element, trap
// Tab within the overlay, and restore focus on close. Returns a cleanup fn.
export function trapFocus(overlay) {
  const prev = document.activeElement;
  const sel = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
  const onKey = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...overlay.querySelectorAll(sel)].filter((el) => !el.disabled && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  overlay.addEventListener('keydown', onKey);
  return () => {
    overlay.removeEventListener('keydown', onKey);
    if (prev && typeof prev.focus === 'function') prev.focus();
  };
}

export function showConfirmDialog(message, onConfirm, onCancel, confirmLabel = 'Kill Anyway') {
  const existing = document.getElementById('confirmOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'confirmOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="confirm-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">${escapeHtml(message)}</div>
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-kill">${escapeHtml(confirmLabel)}</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const teardown = () => { document.removeEventListener('keydown', onEsc); release(); overlay.remove(); };
  const dismiss = () => { teardown(); if (onCancel) onCancel(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); dismiss(); } }
  document.addEventListener('keydown', onEsc);
  overlay.querySelector('.confirm-cancel').focus();
  overlay.querySelector('.confirm-cancel').addEventListener('click', dismiss);
  overlay.querySelector('.confirm-kill').addEventListener('click', () => { teardown(); onConfirm(); });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) dismiss(); });
}

export function askSudoPassword(action, ip, onSubmit) {
  const existing = document.getElementById('sudoOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'sudoOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="confirm-dialog sudo-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">
        <div class="sudo-title">sudo operation</div>
        <div class="sudo-body">
          <strong>${escapeHtml(action)}</strong> runs <code>pfctl</code> as root to modify the firewall.<br>
          Target IP: <code>${escapeHtml(ip)}</code>
        </div>
        <div class="sudo-note">Your password is sent once to the local server and <strong>never stored</strong>.</div>
      </div>
      <input type="password" class="sudo-input" placeholder="System password" autocomplete="off" autocapitalize="off" spellcheck="false" />
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-proceed sudo-submit">Proceed</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const input = overlay.querySelector('.sudo-input');
  input.focus();
  const cleanup = (submitted) => {
    let pwd = submitted ? input.value : '';
    input.value = '';
    document.removeEventListener('keydown', onEsc);
    release();
    overlay.remove();
    return pwd;
  };
  const cancel = () => { cleanup(false); onSubmit(''); };
  const submit = () => onSubmit(cleanup(true));
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); cancel(); } }
  document.addEventListener('keydown', onEsc);
  overlay.querySelector('.confirm-cancel').addEventListener('click', cancel);
  overlay.querySelector('.sudo-submit').addEventListener('click', submit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) cancel(); });
}

export function showVtModal(ip, content, success) {
  const existing = document.getElementById('vtOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'vtOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="vt-modal">
      <div class="vt-modal-header">
        <span class="vt-modal-title">VirusTotal · ${escapeHtml(ip)}</span>
        <button class="vt-modal-close">×</button>
      </div>
      <div class="vt-modal-body">${formatVtOutput(content, success)}</div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const close = () => { document.removeEventListener('keydown', onEsc); release(); overlay.remove(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
  document.addEventListener('keydown', onEsc);
  const closeBtn = overlay.querySelector('.vt-modal-close');
  closeBtn.focus();
  closeBtn.addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

export function formatVtOutput(raw, success) {
  if (success === undefined) return `<div class="vt-loading">${escapeHtml(raw)}</div>`;
  if (!success) return `<pre class="vt-output vt-error">${escapeHtml(raw)}</pre>`;
  const lines = String(raw).split('\n');
  let html = '';
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.includes('malicious:')) {
      const count = parseInt((trimmed.match(/malicious:\s*(\d+)/) || [])[1], 10) || 0;
      html += `<div class="vt-stat-line ${count > 0 ? 'vt-stat-bad' : 'vt-stat-good'}">${escapeHtml(line)}</div>`;
    } else if (trimmed.includes('suspicious:')) {
      const count = parseInt((trimmed.match(/suspicious:\s*(\d+)/) || [])[1], 10) || 0;
      html += `<div class="vt-stat-line ${count > 0 ? 'vt-stat-warn' : 'vt-stat-good'}">${escapeHtml(line)}</div>`;
    } else if (trimmed.includes('harmless:')) {
      html += `<div class="vt-stat-line vt-stat-good">${escapeHtml(line)}</div>`;
    } else if (trimmed.includes('undetected:')) {
      html += `<div class="vt-stat-line vt-stat-neutral">${escapeHtml(line)}</div>`;
    } else if (trimmed.startsWith('-')) {
      html += `<div class="vt-section">${escapeHtml(line)}</div>`;
    } else {
      html += `<div class="vt-line">${escapeHtml(line)}</div>`;
    }
  }
  return `<div class="vt-output">${html}</div>`;
}

// ---------- Blocked sidebar ----------
export function renderBlockedPanel() {
  const { blockedListEl } = el;
  const ips = [...S.blockedIPs];
  const q = S.blockedQ.toLowerCase();
  const filtered = ips.filter(ip => {
    const meta = S.blockedMeta.get(ip);
    const hay = `${ip} ${meta?.country || ''} ${meta?.isp || ''}`.toLowerCase();
    return !q || hay.includes(q);
  });
  if (filtered.length === 0) {
    blockedListEl.innerHTML = `<div class="blocked-empty">${q ? `No blocked addresses match "${escapeHtml(q)}"` : 'No IPs currently blocked'}</div>`;
    return;
  }
  blockedListEl.innerHTML = filtered.map(ip => {
    const meta = S.blockedMeta.get(ip) || {};
    const country = meta.country || '';
    const cc = meta.countryCode || '';
    const isp = meta.isp || '';
    const f = flag(cc);
    const when = meta.blockedAt ? relTime(meta.blockedAt) : '—';
    const ccLabel = f ? `${f} ${escapeHtml(country)}` : escapeHtml(country || '—');
    return `
      <div class="blocked-row" data-ip="${escapeHtml(ip)}">
        <span class="ip">${escapeHtml(ip)}</span>
        <span class="cc">${ccLabel}</span>
        <span class="isp" title="${escapeHtml(isp)}">${escapeHtml(isp)}</span>
        <span class="when">${escapeHtml(when)}</span>
        <button class="un" data-action="unblock" data-ip="${escapeHtml(ip)}">Unblock</button>
      </div>
    `;
  }).join('');
}

// Wire up the blocked sidebar: search input, export button, and bus subscription.
// Called once from main.js init.
export function initBlockedPanel() {
  const { blockedSearch, blockedExport } = el;

  blockedSearch.addEventListener('input', () => {
    S.blockedQ = blockedSearch.value;
    renderBlockedPanel();
  });

  blockedExport.addEventListener('click', () => {
    const rows = [...S.blockedIPs].map(ip => {
      const m = S.blockedMeta.get(ip) || {};
      return `${ip},${m.country || ''},${m.blockedAt ? new Date(m.blockedAt).toISOString() : ''}`;
    });
    const csv = 'ip,country,blockedAt\n' + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'netwatcher-blocked.csv';
    a.click();
  });

  on('blocked:changed', renderBlockedPanel);
}
