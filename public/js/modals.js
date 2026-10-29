import { escapeHtml, flag, relTime, describeBlock, blockRepairStatus, csvCell } from './util.js';
import { el, preserveFocus } from './dom.js';
import { S, on, emit } from './state.js';
import { fetchBlockedIPs } from './api.js';

export function showToast(message, type) {
  document.querySelector('.toast')?.remove();
  const toast = document.createElement('div');
  toast.className = `toast ${type || ''}`;
  toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
  const text = document.createElement('span');
  text.textContent = message;
  const dismiss = document.createElement('button');
  dismiss.textContent = '×';
  dismiss.setAttribute('aria-label', 'Dismiss notification');
  dismiss.addEventListener('click', () => toast.remove());
  toast.append(text, dismiss);
  document.body.appendChild(toast);
  if (type !== 'error') setTimeout(() => toast.remove(), 5000);
}

// Native modal dialogs isolate the background and handle nested Escape/Tab.
export function openDialog(id, html, { onClose, returnFocus } = {}) {
  const overlay = document.createElement('dialog');
  overlay.id = id;
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = html;
  const title = overlay.querySelector('[data-dialog-title]');
  if (title) {
    title.id = `${id}Title`;
    overlay.setAttribute('aria-labelledby', title.id);
  }
  const previous = returnFocus || document.activeElement;
  let closed = false;
  const close = () => {
    if (closed || overlay.dataset.busy === 'true') return;
    closed = true;
    onClose?.(); // Unlock the trigger before restoring focus.
    overlay.close();
    overlay.remove();
    emit('dialog:closed');
    let target = previous?.isConnected ? previous : null;
    if (!target && previous?.dataset.focusKey) {
      target = document.querySelector(`[data-focus-key="${CSS.escape(previous.dataset.focusKey)}"]`);
    }
    if (!target || target.disabled || target === document.body) {
      target = [...document.querySelectorAll('dialog[open]')].at(-1)?.querySelector('button') || el.qEl;
    }
    target?.focus({ preventScroll: true });
  };
  overlay.addEventListener('cancel', (e) => { e.preventDefault(); close(); });
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay || e.target.closest('[data-close]')) close();
  });
  document.body.appendChild(overlay);
  overlay.showModal();
  return { overlay, close };
}

export function showConfirmDialog(message, onConfirm, onCancel, confirmLabel = 'Confirm', returnFocus) {
  let confirmed = false;
  const { overlay, close } = openDialog('confirmOverlay', `
    <div class="confirm-dialog">
      <h2 data-dialog-title class="sudo-title">Confirm action</h2>
      <p class="confirm-message">${escapeHtml(message)}</p>
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel" data-close autofocus>Cancel</button>
        <button class="confirm-btn confirm-kill">${escapeHtml(confirmLabel)}</button>
      </div>
    </div>`, { returnFocus, onClose: () => { if (!confirmed) onCancel?.(); } });
  overlay.querySelector('.confirm-kill').addEventListener('click', () => {
    confirmed = true;
    close();
    onConfirm();
  });
}

export function askSudoPassword(action, target, run, { onClose, returnFocus, context = '' } = {}) {
  const label = action.startsWith('Unblock') ? 'Remove block' : action === 'Re-apply' ? 'Re-apply saved blocks' : 'Block IP';
  const effect = action.startsWith('Unblock')
    ? 'Remove this IP rule for all applications. Other firewall rules may still restrict traffic.'
    : 'Block incoming and outgoing traffic for all applications using these IPs. Shared services may be affected.';
  const { overlay, close } = openDialog('sudoOverlay', `
    <form class="confirm-dialog sudo-dialog">
      <h2 data-dialog-title class="sudo-title">${escapeHtml(label)}</h2>
      <p class="sudo-body"><strong>Target: ${escapeHtml(target)}</strong></p>
      <p class="sudo-body">${effect}</p>
      ${context ? `<p class="sudo-body">${escapeHtml(context)}</p>` : ''}
      <p class="sudo-note">macOS administrator permission is required. Your password is used only for this operation by the local server and never stored. Saved blocks may need reapplying after a restart. Use IP block rules to remove a block.</p>
      <label for="sudoPassword">macOS password</label>
      <input id="sudoPassword" type="password" class="sudo-input" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="sudoError" autofocus />
      <p id="sudoError" class="form-error" role="alert"></p>
      <div class="confirm-actions">
        <button type="button" class="confirm-btn confirm-cancel" data-close>Cancel</button>
        <button class="confirm-btn confirm-proceed sudo-submit" type="submit">${escapeHtml(label)}</button>
      </div>
    </form>`, { onClose, returnFocus });
  const form = overlay.querySelector('form');
  const input = overlay.querySelector('input');
  const error = overlay.querySelector('.form-error');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (overlay.dataset.busy === 'true') return;
    if (!input.value) {
      error.textContent = 'Enter your macOS password to continue.';
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      return;
    }
    let password = input.value;
    input.value = '';
    error.textContent = '';
    input.removeAttribute('aria-invalid');
    overlay.dataset.busy = 'true';
    form.setAttribute('aria-busy', 'true');
    form.querySelectorAll('button, input').forEach(el => { el.disabled = true; });
    const submit = form.querySelector('[type="submit"]');
    submit.textContent = 'Working…';
    try {
      const pending = run(password);
      password = '';
      const result = await pending;
      if (!result?.success) throw new Error(result?.message || 'Operation failed. Try again.');
      overlay.dataset.busy = 'false';
      close();
      showToast(result.message || 'Firewall rule updated', 'success');
    } catch (err) {
      error.textContent = err.message;
      input.setAttribute('aria-invalid', 'true');
    } finally {
      password = '';
      overlay.dataset.busy = 'false';
      form.removeAttribute('aria-busy');
      form.querySelectorAll('button, input').forEach(el => { el.disabled = false; });
      submit.textContent = label;
      if (overlay.isConnected) input.focus();
    }
  });
}

export function showVtModal(ip, content, success, options) {
  return openDialog('vtOverlay', `
    <div class="vt-modal">
      <div class="vt-modal-header">
        <h2 data-dialog-title class="vt-modal-title">VirusTotal · ${escapeHtml(ip)}</h2>
        <button class="vt-modal-close" data-close aria-label="Close VirusTotal" autofocus>×</button>
      </div>
      <p class="reputation-note panel-note">IP reputation from VirusTotal via your local CLI.</p>
      <div class="vt-modal-body" aria-live="polite">${formatVtOutput(content, success)}</div>
    </div>`, options);
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
  const restoreFocus = preserveFocus(blockedListEl);
  const repair = S.historyFresh ? blockRepairStatus(S.pfIPs, S.blockedMeta, S.firewallStatus) : null;
  const banner = repair
    ? `<div class="blocked-stale-banner" ${repair.urgent ? 'role="alert"' : ''}>${escapeHtml(repair.message)} <button type="button" class="blocked-reapply-btn" data-action="reapply-blocks" data-focus-key="reapply">Re-apply all</button></div>`
    : '';
  const ips = [...S.blockedIPs];
  const q = S.blockedQ.toLowerCase();
  const filtered = ips.filter(ip => {
    const meta = S.blockedMeta.get(ip);
    const hay = `${ip} ${meta?.country || ''} ${meta?.isp || ''}`.toLowerCase();
    return !q || hay.includes(q);
  });
  if (filtered.length === 0) {
    blockedListEl.innerHTML = banner + `<div class="blocked-empty">${q ? `No blocked addresses match "${escapeHtml(q)}"` : S.historyError ? 'Saved rules unavailable. Retry the check.' : 'No saved IP block rules'}</div>`;
    restoreFocus();
    return;
  }
  blockedListEl.innerHTML = banner + filtered.map(ip => {
    const meta = S.blockedMeta.get(ip) || {};
    const status = describeBlock(ip, S.pfIPs, S.blockedMeta, S.staleCount, S.historyFresh, S.firewallStatus);
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
        <span class="blocked-tag ${status.kind}">${status.label}</span>
        <button class="un" data-focus-key="unblock-${escapeHtml(ip)}" data-action="unblock" data-ip="${escapeHtml(ip)}">Unblock</button>
      </div>
    `;
  }).join('');
  restoreFocus();
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
      const status = describeBlock(ip, S.pfIPs, S.blockedMeta, S.staleCount, S.historyFresh, S.firewallStatus);
      return [ip, m.country || '', m.blockedAt ? new Date(m.blockedAt).toISOString() : '', status.label].map(csvCell).join(',');
    });
    const csv = 'ip,country,blockedAt,status\n' + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'netwatcher-blocked.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  const retry = document.getElementById('blockedRetry');
  retry.addEventListener('click', () => fetchBlockedIPs());
  on('blocked:changed', renderBlockedPanel);
}
