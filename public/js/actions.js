/* ============================================================
   NetWatcher — privileged client actions + blocked-history modal
   ============================================================ */

import { escapeHtml, looksLikeIP, formatTime } from './util.js';
import { el } from './dom.js';
import { S } from './state.js';
import { apiFetch, sendFirewallRequest, fetchBlockedIPs, fetchConnections } from './api.js';
import { showToast, trapFocus, showConfirmDialog, askSudoPassword, showVtModal } from './modals.js';

// ---------- In-flight button lock ----------
// Disables the triggering button while its action is in flight (prevents
// double-click / double-sudo). Returns an unlock() that only re-enables the
// button if it is still in the DOM (a renderQueue() rebuild may have
// replaced it — the isConnected guard handles that).
export function lockBtn(btn) {
  if (!btn) return () => {};
  btn.disabled = true;
  return () => { if (btn.isConnected) btn.disabled = false; };
}

// ---------- Block / Unblock ----------
export function blockIPAction(ip, btn) {
  const unlock = lockBtn(btn);
  askSudoPassword('Block', ip, async (password) => {
    if (!password) { unlock(); return; }
    try {
      const result = await sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password);
      password = '';
      showToast(result.message, result.success ? 'success' : 'error');
      if (result.success) {
        S.blockedIPs.add(ip);
        await fetchBlockedIPs();
      }
    } catch (err) {
      showToast('Failed to block IP: ' + err.message, 'error');
    } finally {
      unlock();
    }
  });
}

export function unblockIPAction(ip, btn) {
  const unlock = lockBtn(btn);
  askSudoPassword('Unblock', ip, async (password) => {
    if (!password) { unlock(); return; }
    try {
      const result = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
      password = '';
      showToast(result.message, result.success ? 'success' : 'error');
      if (result.success) {
        S.blockedIPs.delete(ip);
        await fetchBlockedIPs();
      }
    } catch (err) {
      showToast('Failed to unblock IP: ' + err.message, 'error');
    } finally {
      unlock();
    }
  });
}

// ---------- Kill ----------
export function killProcessAction(pid, name, isSystem, btn) {
  const unlock = lockBtn(btn);
  const message = isSystem
    ? `"${name}" is a system process required for system stability. Are you sure you want to kill it?`
    : `Kill "${name}" (PID ${pid})? This sends SIGTERM and can't be undone.`;
  showConfirmDialog(message, () => doKill(pid, unlock), unlock, isSystem ? 'Kill Anyway' : 'Kill Process');
}

// PIDs with an in-flight SIGTERM. Guards against a second kill of the same PID
// even if a 2s-poll re-render rebuilds the (lock-bearing) button mid-confirm.
// killsInFlight is read from S (shared state object).
export async function doKill(pid, unlock) {
  const killsInFlight = S.killsInFlight;
  if (killsInFlight.has(pid)) { if (unlock) unlock(); return; }
  killsInFlight.add(pid);
  try {
    const res = await apiFetch(`/api/kill/${pid}`, { method: 'POST' });
    const result = await res.json();
    showToast(result.message, result.success ? 'success' : 'error');
    setTimeout(fetchConnections, 500);
  } catch (err) {
    showToast('Failed to kill process: ' + err.message, 'error');
  } finally {
    killsInFlight.delete(pid);
    if (unlock) unlock();
  }
}

// ---------- VirusTotal ----------
export async function vtCheckAction(ip, btn) {
  const unlock = lockBtn(btn);
  showVtModal(ip, 'Loading VirusTotal data…');
  try {
    const res = await apiFetch(`/api/vt/${encodeURIComponent(ip)}`);
    const data = await res.json();
    showVtModal(ip, data.output, data.success);
  } catch (err) {
    showVtModal(ip, 'Failed to reach VT endpoint: ' + err.message, false);
  } finally {
    unlock();
  }
}

// ---------- Manual block IP ----------
export function blockIPManualAction(overlay, selectMode) {
  const existing = document.getElementById('manualBlockOverlay');
  if (existing) existing.remove();
  const dialog = document.createElement('div');
  dialog.id = 'manualBlockOverlay';
  dialog.className = 'confirm-overlay';
  dialog.setAttribute('role', 'dialog');
  dialog.setAttribute('aria-modal', 'true');
  dialog.innerHTML = `
    <div class="confirm-dialog sudo-dialog">
      <div class="confirm-icon">⚠</div>
      <div class="confirm-message">
        <div class="sudo-title">Block IP manually</div>
        <div class="sudo-body">Add an IPv4 or IPv6 address to the <code>pfctl</code> block table.</div>
      </div>
      <input type="text" class="sudo-input manual-ip-input" placeholder="e.g. 1.2.3.4" autocomplete="off" />
      <div class="confirm-actions">
        <button class="confirm-btn confirm-cancel">Cancel</button>
        <button class="confirm-btn confirm-kill manual-submit">Continue</button>
      </div>
    </div>
  `;
  document.body.appendChild(dialog);
  const release = trapFocus(dialog);
  const input = dialog.querySelector('.manual-ip-input');
  input.focus();
  const close = () => { document.removeEventListener('keydown', onEsc); release(); dialog.remove(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
  document.addEventListener('keydown', onEsc);
  const submit = () => {
    const ip = input.value.trim();
    if (!looksLikeIP(ip)) { showToast('Invalid IP format', 'error'); input.focus(); return; }
    close();
    askSudoPassword('Block', ip, async (password) => {
      if (!password) return;
      try {
        const r = await sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password);
        password = '';
        showToast(r.message, r.success ? 'success' : 'error');
        if (r.success) {
          S.blockedIPs.add(ip);
          await fetchBlockedIPs();
          if (overlay) await renderBlockedListBody(overlay, { selectMode });
        }
      } catch (err) { showToast('Failed to block IP: ' + err.message, 'error'); }
    });
  };
  dialog.querySelector('.confirm-cancel').addEventListener('click', close);
  dialog.querySelector('.manual-submit').addEventListener('click', submit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
  });
  dialog.addEventListener('click', (e) => { if (e.target === dialog) close(); });
}

// ---------- Bulk unblock ----------
export function unblockBulkAction(ips, overlay) {
  const representative = ips.length === 1 ? ips[0] : `${ips[0]} + ${ips.length - 1} more`;
  askSudoPassword(`Unblock ${ips.length} IP${ips.length === 1 ? '' : 's'}`, representative, async (password) => {
    if (!password) return;
    let ok = 0, fail = 0, aborted = false;
    try {
      for (const ip of ips) {
        try {
          const r = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
          if (r.success) { ok += 1; S.blockedIPs.delete(ip); }
          else {
            fail += 1;
            if (typeof r.message === 'string' && /sudo authentication/i.test(r.message)) { aborted = true; break; }
          }
        } catch { fail += 1; }
      }
    } finally { password = ''; }
    const remaining = ips.length - ok - fail;
    const msg = aborted
      ? `Aborted — sudo auth failed. Unblocked ${ok}, skipped ${remaining}.`
      : fail === 0 ? `Unblocked ${ok} IP${ok === 1 ? '' : 's'}` : `Unblocked ${ok}, failed ${fail}`;
    showToast(msg, fail === 0 && !aborted ? 'success' : 'error');
    await fetchBlockedIPs();
    await renderBlockedListBody(overlay, { selectMode: false });
  });
}

// ---------- Blocked-history modal ----------
export async function showBlockedListModal() {
  const existing = document.getElementById('blockedListOverlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'blockedListOverlay';
  overlay.className = 'confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.innerHTML = `
    <div class="blocked-modal">
      <div class="vt-modal-header">
        <span class="vt-modal-title">Blocked IPs · History</span>
        <button class="vt-modal-close" data-close="1">×</button>
      </div>
      <div class="blocked-modal-body"><div class="vt-loading">Loading…</div></div>
    </div>
  `;
  document.body.appendChild(overlay);
  const release = trapFocus(overlay);
  const close = () => { document.removeEventListener('keydown', onEsc); release(); overlay.remove(); };
  function onEsc(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
  document.addEventListener('keydown', onEsc);
  overlay.querySelector('.vt-modal-close')?.focus();
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay || e.target.dataset.close === '1') close();
  });
  await renderBlockedListBody(overlay, { selectMode: false });
}

export async function renderBlockedListBody(overlay, { selectMode }) {
  const body = overlay.querySelector('.blocked-modal-body');
  body.innerHTML = '<div class="vt-loading">Loading…</div>';
  let data;
  try {
    const res = await apiFetch('/api/block-history');
    data = await res.json();
  } catch (err) {
    body.innerHTML = `<div class="vt-output vt-error">Failed to load: ${escapeHtml(err.message)}</div>`;
    return;
  }
  const rows = buildBlockedRows(data.history || []);
  const hasActive = rows.some(r => r.status === 'active');
  const effectiveSelect = selectMode && hasActive;
  const toolbar = `
    <div class="blocked-toolbar">
      <button data-action="manual-add">+ Block IP…</button>
      <button class="${effectiveSelect ? 'active' : ''}" ${hasActive ? '' : 'disabled'} data-action="toggle-select">${effectiveSelect ? 'Cancel' : 'Select'}</button>
      <button data-action="unblock-selected" ${effectiveSelect ? '' : 'hidden'} disabled>Unblock Selected <span class="blocked-sel-count">(0)</span></button>
    </div>
  `;
  if (rows.length === 0) {
    body.innerHTML = toolbar + '<div class="blocked-empty">No blocks recorded yet.</div>';
    wireBlockedToolbar(body, overlay, effectiveSelect);
    return;
  }
  body.innerHTML = toolbar + `
    <table class="blocked-table ${effectiveSelect ? 'select-mode' : ''}">
      <thead><tr>
        ${effectiveSelect ? '<th></th>' : ''}
        <th>IP</th><th>Country</th><th>Blocked At</th><th>Status</th><th></th>
      </tr></thead>
      <tbody>${rows.map(r => {
        const isActive = r.status === 'active';
        const ipEsc = escapeHtml(r.ip);
        return `<tr data-ip="${ipEsc}" data-active="${isActive ? '1' : '0'}">
          ${effectiveSelect ? `<td>${isActive ? `<input type="checkbox" class="blocked-row-check">` : ''}</td>` : ''}
          <td><code>${ipEsc}</code></td>
          <td>${r.country ? escapeHtml(r.country) : '<span class="geo-unknown">-</span>'}</td>
          <td>${escapeHtml(formatTime(r.blockedAt))}</td>
          <td>${isActive
            ? '<span class="blocked-tag">ACTIVE</span>'
            : r.status === 'superseded'
              ? `<span class="geo-unknown">Replaced ${escapeHtml(formatTime(r.unblockedAt))}</span>`
              : `<span class="geo-unknown">Unblocked ${escapeHtml(formatTime(r.unblockedAt))}</span>`}</td>
          <td>${isActive
            ? `<button class="blocked-row-unblock" data-unblock="${ipEsc}">Unblock</button>`
            : `<span class="blocked-row-actions">
                 <button class="blocked-row-reblock icon-btn" data-reblock="${ipEsc}" title="Re-block">⟲</button>
                 <button class="blocked-row-remove icon-btn" data-remove="${ipEsc}"
                   data-blocked-at="${r.blockedAt}"
                   ${r.status === 'unblocked' ? `data-unblocked-at="${r.unblockedAt}"` : ''}
                   title="Delete row">🗑</button>
               </span>`}
          </td>
        </tr>`;
      }).join('')}
      </tbody>
    </table>
  `;
  wireBlockedToolbar(body, overlay, effectiveSelect);
}

function wireBlockedToolbar(body, overlay, selectMode) {
  const toggleBtn = body.querySelector('[data-action="toggle-select"]');
  const bulkBtn = body.querySelector('[data-action="unblock-selected"]');
  const addBtn = body.querySelector('[data-action="manual-add"]');
  const countEl = body.querySelector('.blocked-sel-count');
  const updateBulkState = () => {
    const n = body.querySelectorAll('.blocked-row-check:checked').length;
    if (countEl) countEl.textContent = `(${n})`;
    if (bulkBtn) bulkBtn.disabled = n === 0;
  };
  if (toggleBtn) toggleBtn.addEventListener('click', () => renderBlockedListBody(overlay, { selectMode: !selectMode }));
  if (addBtn) addBtn.addEventListener('click', () => blockIPManualAction(overlay, selectMode));
  body.querySelectorAll('.blocked-row-check').forEach(cb => cb.addEventListener('change', updateBulkState));
  if (bulkBtn) bulkBtn.addEventListener('click', () => {
    const ips = Array.from(body.querySelectorAll('.blocked-row-check:checked')).map(cb => cb.closest('tr')?.dataset.ip).filter(Boolean);
    if (ips.length === 0) return;
    unblockBulkAction(ips, overlay);
  });
  // [762] — per-row Unblock: use lockBtn to prevent double-submit
  body.querySelectorAll('.blocked-row-unblock').forEach(btn => {
    btn.addEventListener('click', () => {
      const ip = btn.dataset.unblock;
      const unlock = lockBtn(btn);
      askSudoPassword('Unblock', ip, async (password) => {
        if (!password) { unlock(); return; }
        try {
          const r = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
          password = '';
          showToast(r.message, r.success ? 'success' : 'error');
          if (r.success) { S.blockedIPs.delete(ip); await fetchBlockedIPs(); await renderBlockedListBody(overlay, { selectMode }); }
        } catch (err) { showToast('Failed to unblock IP: ' + err.message, 'error'); }
        finally { unlock(); }
      });
    });
  });
  // [762] — per-row Reblock: use lockBtn to prevent double-submit
  body.querySelectorAll('.blocked-row-reblock').forEach(btn => {
    btn.addEventListener('click', () => {
      const ip = btn.dataset.reblock;
      const unlock = lockBtn(btn);
      askSudoPassword('Block', ip, async (password) => {
        if (!password) { unlock(); return; }
        try {
          const r = await sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password);
          password = '';
          showToast(r.message, r.success ? 'success' : 'error');
          if (r.success) { S.blockedIPs.add(ip); await fetchBlockedIPs(); await renderBlockedListBody(overlay, { selectMode }); }
        } catch (err) { showToast('Failed to reblock IP: ' + err.message, 'error'); }
        finally { unlock(); }
      });
    });
  });
  // [762] — per-row Remove: replace hand-rolled disable/restore with lockBtn
  body.querySelectorAll('.blocked-row-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.remove;
      const blockedAt = btn.dataset.blockedAt;
      if (!ip || !blockedAt) return;
      const unlock = lockBtn(btn);
      try {
        const q = new URLSearchParams({ blockedAt });
        if (btn.dataset.unblockedAt) q.set('unblockedAt', btn.dataset.unblockedAt);
        const res = await apiFetch(`/api/block-history/${encodeURIComponent(ip)}?${q}`, { method: 'DELETE' });
        const result = await res.json();
        if (res.ok && result.success) {
          showToast(result.removed === 0 ? `Nothing to remove for ${ip}` : `Removed row for ${ip}`, 'success');
          await renderBlockedListBody(overlay, { selectMode });
        } else {
          showToast(result.message || 'Failed to remove row', 'error');
        }
      } catch (err) {
        showToast('Failed to remove row: ' + err.message, 'error');
      } finally {
        unlock();
      }
    });
  });
}

export function buildBlockedRows(history) {
  const byIp = new Map();
  for (const ev of history) {
    if (!byIp.has(ev.ip)) byIp.set(ev.ip, []);
    byIp.get(ev.ip).push(ev);
  }
  const rows = [];
  for (const [ip, events] of byIp) {
    events.sort((a, b) => a.at - b.at);
    let pending = null;
    for (const ev of events) {
      if (ev.action === 'block') {
        if (pending) rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'superseded', unblockedAt: ev.at });
        pending = ev;
      } else if (ev.action === 'unblock' && pending) {
        rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'unblocked', unblockedAt: ev.at });
        pending = null;
      }
    }
    if (pending) rows.push({ ip, country: pending.country ?? null, blockedAt: pending.at, status: 'active' });
  }
  const rank = (s) => (s === 'active' ? 0 : 1);
  rows.sort((a, b) => rank(a.status) - rank(b.status) || b.blockedAt - a.blockedAt);
  return rows;
}

// ---------- Init: wire the blocked-sidebar + history button listeners ----------
export function initActions() {
  const { blockedListEl, blockedAdd, blockedHistoryBtn } = el;
  blockedAdd.addEventListener('click', () => blockIPManualAction());
  blockedHistoryBtn.addEventListener('click', () => showBlockedListModal());
  blockedListEl.addEventListener('click', (e) => {
    const b = e.target.closest('[data-action="unblock"]');
    if (!b) return;
    unblockIPAction(b.dataset.ip, b);
  });
}
