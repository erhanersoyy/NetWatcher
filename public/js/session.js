// Keep the launch capability out of query strings, Referer, persistent storage and API logs.
export async function establishSession() {
  let access = new URLSearchParams(location.hash.slice(1)).get('access');
  if (access) history.replaceState(null, '', location.pathname + location.search);
  try {
    const headers = { 'x-requested-by': 'netwatcher' };
    if (access) headers.Authorization = `Bearer ${access}`;
    const response = await fetch('/api/session', { method: access ? 'POST' : 'GET', headers });
    return response.ok;
  } catch { return false; }
  finally { access = ''; }
}

export function showSessionRequired() {
  if (document.getElementById('sessionRequired')) return;
  const dialog = document.createElement('dialog');
  dialog.id = 'sessionRequired';
  dialog.className = 'confirm-overlay';
  dialog.setAttribute('aria-labelledby', 'sessionTitle');
  dialog.innerHTML = '<div class="confirm-dialog"><h2 id="sessionTitle" class="sudo-title">Open your private access link</h2><p class="sudo-body">Use the link printed in the terminal when NetWatcher starts. Access expires after 12 hours or a server restart.</p><p class="sudo-note">The link grants access to this local monitor. Keep it private. Refresh this page if the server was temporarily unavailable.</p><button class="confirm-btn" id="sessionRetry" autofocus>Retry connection</button></div>';
  dialog.addEventListener('cancel', event => event.preventDefault());
  document.body.appendChild(dialog);
  dialog.querySelector('button').addEventListener('click', () => location.reload());
  dialog.showModal();
}

// Pasting the terminal link into an already-open locked page may only change its hash.
globalThis.addEventListener?.('hashchange', () => {
  if (new URLSearchParams(location.hash.slice(1)).has('access')) location.reload();
});
