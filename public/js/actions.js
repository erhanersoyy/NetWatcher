import { escapeHtml, looksLikeIP, formatTime, describeBlock } from './util.js';
import { el, preserveFocus } from './dom.js';
import { S } from './state.js';
import { apiFetch, sendFirewallRequest, fetchBlockedIPs, fetchConnections, reapplyBlocks } from './api.js';
import { showToast, openDialog, showConfirmDialog, askSudoPassword, showVtModal, formatVtOutput } from './modals.js';

export function lockBtn(btn) {
  if (!btn) return () => {};
  btn.disabled = true;
  return () => { if (btn.isConnected) btn.disabled = false; };
}

function firewallAction(action, ip, btn, request, afterUpdate) {
  const unlock = lockBtn(btn);
  const processes = (S.lastData || []).filter(p => p.connections.some(c => c.remoteAddress === ip));
  const context = processes.length ? `Currently used by: ${processes.map(p => p.processName).join(', ')}.` : '';
  askSudoPassword(action, ip, async password => {
    const pending = request(password);
    password = '';
    const result = await pending;
    await fetchBlockedIPs();
    await afterUpdate?.();
    if (result.success) return result;
    if (result.failed?.length) return { ...result, message: `${result.applied.length} applied; ${result.failed.length} failed. ${result.failed.map(f => `${f.ip}: ${f.message}`).join('; ')}` };
    return result;
  }, { onClose: unlock, returnFocus: btn, context });
}

export function blockIPAction(ip, btn, afterUpdate) {
  firewallAction('Block', ip, btn, password => sendFirewallRequest(`/api/block/${encodeURIComponent(ip)}`, ip, password), afterUpdate);
}
export function unblockIPAction(ip, btn, afterUpdate) {
  firewallAction('Unblock', ip, btn, password => sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password), afterUpdate);
}
export function reapplyBlocksAction(btn) {
  firewallAction('Re-apply', `${S.blockedMeta.size} saved IP rules`, btn, reapplyBlocks);
}

export function killProcessAction(pid, name, isSystem, btn) {
  const identity = S.lastData?.find(p => p.pid === pid)?.identity;
  if (!identity?.token) { showToast('Process identity unavailable. Refresh the connection list before ending a process.', 'error'); return; }
  const message = `End "${name}" (PID ${pid})? ${isSystem ? 'This has a name-based system label; ending a system process may disrupt macOS. ' : ''}Unsaved work may be lost. This sends SIGTERM and cannot be undone.`;
  showConfirmDialog(message, () => doKill(pid, identity.token, lockBtn(btn)), undefined, 'End process', btn);
}
export async function doKill(pid, identityToken, unlock) {
  if (S.killsInFlight.has(pid)) { unlock?.(); return; }
  S.killsInFlight.add(pid);
  try {
    const res = await apiFetch(`/api/kill/${pid}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identityToken }) });
    const result = await res.json();
    showToast(result.message, result.success ? 'success' : 'error');
    setTimeout(() => fetchConnections({ force: true }), 500);
  } catch (err) {
    showToast(`Could not end process: ${err.message}`, 'error');
  } finally { S.killsInFlight.delete(pid); unlock?.(); }
}

export async function vtCheckAction(ip, btn) {
  const unlock = lockBtn(btn);
  const { overlay } = showVtModal(ip, 'Loading VirusTotal data…', undefined, { onClose: unlock, returnFocus: btn });
  try {
    const res = await apiFetch(`/api/vt/${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (overlay.isConnected) {
      const time = data.queriedAt ? new Date(data.queriedAt).toLocaleString() : 'unavailable';
      const analysis = data.analysisAt ? new Date(data.analysisAt).toLocaleString() : 'not supplied';
      overlay.querySelector('.vt-modal-body').innerHTML = `<p class="panel-note">Retrieved: ${escapeHtml(time)}${data.cached ? ' · cached' : ''}<br>Provider analysis: ${escapeHtml(analysis)}</p>` + formatVtOutput(data.output, data.success);
    }
  } catch (err) {
    if (overlay.isConnected) overlay.querySelector('.vt-modal-body').innerHTML = formatVtOutput(`Could not load reputation data: ${err.message}`, false);
  } finally { unlock(); }
}

export function blockIPManualAction(historyOverlay, selectMode = false, trigger = el.blockedAdd) {
  const { overlay, close } = openDialog('manualBlockOverlay', `
    <form class="confirm-dialog sudo-dialog">
      <h2 data-dialog-title class="sudo-title">Add an IP block rule</h2>
      <p class="sudo-body">The rule applies to all applications. Administrator permission is requested in the next step.</p>
      <label for="manualIP">IPv4 or IPv6 address</label>
      <input id="manualIP" class="sudo-input manual-ip-input" placeholder="e.g. 203.0.113.10" autocomplete="off" aria-describedby="manualError" autofocus />
      <p id="manualError" class="form-error" role="alert"></p>
      <div class="confirm-actions">
        <button type="button" class="confirm-btn" data-close>Cancel</button>
        <button type="submit" class="confirm-btn confirm-proceed">Continue</button>
      </div>
    </form>`, { returnFocus: trigger });
  overlay.querySelector('form').addEventListener('submit', e => {
    e.preventDefault();
    const input = overlay.querySelector('input');
    const ip = input.value.trim();
    if (!looksLikeIP(ip)) {
      overlay.querySelector('.form-error').textContent = 'Enter a valid IPv4 or IPv6 address, without a port or URL.';
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      return;
    }
    close();
    blockIPAction(ip, null, historyOverlay ? () => renderBlockedListBody(historyOverlay, { selectMode }) : undefined);
  });
}

export function unblockBulkAction(ips, overlay) {
  const remaining = new Set(ips);
  askSudoPassword('Unblock', `${ips.length} selected IP rules`, async password => {
    let failure = '';
    try {
      for (const ip of [...remaining]) {
        const result = await sendFirewallRequest(`/api/unblock/${encodeURIComponent(ip)}`, ip, password);
        if (result.success) remaining.delete(ip);
        else { failure = result.message || 'Could not remove rule'; break; }
      }
    } catch (err) { failure = err.message; }
    finally { password = ''; }
    await fetchBlockedIPs();
    await renderBlockedListBody(overlay, { selectMode: false });
    return { success: remaining.size === 0, message: remaining.size
      ? `${ips.length - remaining.size} removed; ${remaining.size} remain. ${failure} Retry applies only to remaining rules.`
      : `Removed ${ips.length} IP rules` };
  });
}

export async function showBlockedListModal() {
  const { overlay } = openDialog('blockedListOverlay', `
    <div class="blocked-modal">
      <div class="vt-modal-header">
        <h2 data-dialog-title class="vt-modal-title">IP block rules · History</h2>
        <button class="vt-modal-close" data-close aria-label="Close history" autofocus>×</button>
      </div>
      <div class="blocked-modal-body"><p>Loading history…</p></div>
    </div>`, { returnFocus: el.blockedHistoryBtn });
  await fetchBlockedIPs();
  if (overlay.isConnected) renderBlockedListBody(overlay, { selectMode: false });
}

export function renderBlockedListBody(overlay, { selectMode }) {
  if (!overlay?.isConnected) return;
  const body = overlay.querySelector('.blocked-modal-body');
  const restoreFocus = preserveFocus(body);
  const query = body.querySelector('[data-history-search]')?.value || '';
  const status = body.querySelector('[data-history-status]')?.value || 'all';
  const rows = buildBlockedRows(S.historyData?.history || []);
  const effectiveSelect = selectMode && rows.some(r => r.status === 'active');
  body.innerHTML = `
    ${S.historyError ? `<p class="form-error" role="alert">${escapeHtml(S.historyError)}. Last known history is shown.</p>` : ''}
    <p class="panel-note">Saved rules and firewall-table membership are distinct. “In firewall table” does not confirm traffic is blocked.</p>
    <div class="blocked-toolbar">
      <button data-action="history-retry">Refresh status</button>
      <button data-action="manual-add" data-focus-key="history-add">+ Block IP…</button>
      <button data-action="toggle-select" data-focus-key="history-select" ${rows.some(r => r.status === 'active') ? '' : 'disabled'}>${effectiveSelect ? 'Cancel selection' : 'Select rules'}</button>
      <button data-action="unblock-selected" ${effectiveSelect ? '' : 'hidden'} disabled>Remove selected <span class="blocked-sel-count">(0)</span></button>
    </div>
    <div class="history-filters">
      <label>Search IP or country<input data-history-search data-focus-key="history-search" value="${escapeHtml(query)}" type="search" /></label>
      <label>Status<select data-history-status data-focus-key="history-status"><option value="all">All history</option><option value="active">Saved rules</option><option value="unblocked">Removed</option><option value="superseded">Replaced</option></select></label>
    </div>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Block history table">
      <table class="blocked-table"><thead><tr>${effectiveSelect ? '<th scope="col">Select</th>' : ''}<th scope="col">IP</th><th scope="col">Country</th><th scope="col">Saved at</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead>
      <tbody>${rows.map(r => {
        const ip = escapeHtml(r.ip), active = r.status === 'active';
        const state = describeBlock(r.ip, S.pfIPs, S.blockedMeta, S.staleCount, S.historyFresh, S.firewallStatus);
        return `<tr data-ip="${ip}" data-status="${r.status}" data-search="${escapeHtml(`${r.ip} ${r.country || ''}`.toLowerCase())}">
          ${effectiveSelect ? `<td>${active ? `<input type="checkbox" class="blocked-row-check" aria-label="Select ${ip}" data-focus-key="select-${ip}">` : ''}</td>` : ''}
          <td><code>${ip}</code></td><td>${escapeHtml(r.country || 'Unknown')}</td><td>${escapeHtml(formatTime(r.blockedAt))}</td>
          <td>${active ? `<span class="blocked-tag ${state.kind}">${state.label}</span>` : `${r.status === 'superseded' ? 'Replaced' : 'Removed'} ${escapeHtml(formatTime(r.unblockedAt))}`}</td>
          <td>${active ? `<button data-unblock="${ip}" data-focus-key="history-unblock-${ip}">Remove block</button>` : `<div class="blocked-row-actions"><button data-reblock="${ip}" data-focus-key="history-reblock-${ip}-${r.blockedAt}">Re-block</button><button data-remove="${ip}" data-blocked-at="${r.blockedAt}" ${r.status === 'unblocked' ? `data-unblocked-at="${r.unblockedAt}"` : ''} data-focus-key="history-delete-${ip}-${r.blockedAt}">Delete record</button></div>`}</td>
        </tr>`;
      }).join('')}</tbody></table>
    </div>
    <p class="blocked-empty" data-history-empty hidden>No history matches these filters.</p>`;
  const statusSelect = body.querySelector('[data-history-status]');
  statusSelect.value = status;
  const countSelection = () => {
    const n = body.querySelectorAll('.blocked-row-check:checked').length;
    body.querySelector('.blocked-sel-count').textContent = `(${n})`;
    body.querySelector('[data-action="unblock-selected"]').disabled = n === 0;
  };
  const filter = () => {
    const q = body.querySelector('[data-history-search]').value.toLowerCase().trim();
    let visible = 0;
    body.querySelectorAll('tr[data-ip]').forEach(row => {
      row.hidden = !row.dataset.search.includes(q) || (statusSelect.value !== 'all' && row.dataset.status !== statusSelect.value);
      if (row.hidden) { const cb = row.querySelector('input'); if (cb) cb.checked = false; }
      else visible++;
    });
    body.querySelector('[data-history-empty]').hidden = visible > 0;
    countSelection();
  };
  body.querySelector('[data-history-search]').addEventListener('input', filter);
  statusSelect.addEventListener('change', filter);
  body.querySelectorAll('.blocked-row-check').forEach(cb => cb.addEventListener('change', countSelection));
  body.querySelector('[data-action="history-retry"]').addEventListener('click', async () => { await fetchBlockedIPs(); renderBlockedListBody(overlay, { selectMode }); });
  body.querySelector('[data-action="toggle-select"]').addEventListener('click', () => renderBlockedListBody(overlay, { selectMode: !selectMode }));
  body.querySelector('[data-action="manual-add"]').addEventListener('click', e => blockIPManualAction(overlay, selectMode, e.currentTarget));
  body.querySelector('[data-action="unblock-selected"]').addEventListener('click', () => {
    const ips = [...body.querySelectorAll('.blocked-row-check:checked')].map(cb => cb.closest('tr').dataset.ip);
    if (ips.length) unblockBulkAction(ips, overlay);
  });
  const update = () => renderBlockedListBody(overlay, { selectMode });
  body.querySelectorAll('[data-unblock]').forEach(btn => btn.addEventListener('click', () => unblockIPAction(btn.dataset.unblock, btn, update)));
  body.querySelectorAll('[data-reblock]').forEach(btn => btn.addEventListener('click', () => blockIPAction(btn.dataset.reblock, btn, update)));
  body.querySelectorAll('[data-remove]').forEach(btn => btn.addEventListener('click', () => {
    showConfirmDialog(`Delete the history record for ${btn.dataset.remove}, saved ${formatTime(Number(btn.dataset.blockedAt))}? This cannot be undone. It does not change firewall rules.`, async () => {
      const unlock = lockBtn(btn);
      try {
        const query = new URLSearchParams({ blockedAt: btn.dataset.blockedAt });
        if (btn.dataset.unblockedAt) query.set('unblockedAt', btn.dataset.unblockedAt);
        const res = await apiFetch(`/api/block-history/${encodeURIComponent(btn.dataset.remove)}?${query}`, { method: 'DELETE' });
        const result = await res.json();
        if (!res.ok || !result.success) throw new Error(result.message || 'Could not delete record');
        await fetchBlockedIPs(); update();
        showToast('History record deleted', 'success');
      } catch (err) {
        const error = document.createElement('p');
        error.className = 'form-error'; error.setAttribute('role', 'alert'); error.textContent = err.message;
        body.prepend(error);
      } finally { unlock(); }
    }, undefined, 'Delete record', btn);
  }));
  filter();
  restoreFocus();
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

export function initActions() {
  el.blockedAdd.addEventListener('click', () => blockIPManualAction());
  el.blockedHistoryBtn.addEventListener('click', () => showBlockedListModal());
  el.blockedListEl.addEventListener('click', e => {
    const reapply = e.target.closest('[data-action="reapply-blocks"]');
    if (reapply) { reapplyBlocksAction(reapply); return; }
    const button = e.target.closest('[data-action="unblock"]');
    if (button) unblockIPAction(button.dataset.ip, button);
  });
}
