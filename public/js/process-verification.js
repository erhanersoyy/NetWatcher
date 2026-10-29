import { escapeHtml } from './util.js';

export function verificationLabel(v) {
  if (!v) return { text: 'Verification unavailable', tone: 'muted' };
  if (v.state === 'queued') return { text: 'Verification queued', tone: 'muted' };
  if (v.state === 'checking') return { text: 'Checking signature…', tone: 'muted' };
  if (v.signature === 'invalid') return { text: 'Signature invalid', tone: 'failed' };
  if (v.hashChanged) return { text: 'Executable changed', tone: 'changed' };
  if (v.signature === 'valid') return { text: 'Signature valid', tone: 'verified' };
  if (v.signature === 'ad-hoc') return { text: 'Ad-hoc signature', tone: 'muted' };
  if (v.signature === 'unsigned') return { text: 'Unsigned', tone: 'muted' };
  return { text: 'Verification unavailable', tone: 'muted' };
}

export function renderVerificationBadge(v) {
  const label = verificationLabel(v);
  return `<span class="verification-status ${label.tone}" title="Automatic check of the on-disk executable">${label.text}</span>`;
}

export function renderVerificationDetails(v) {
  if (!v) return '';
  const lines = ['<span>On-disk executable</span>'];
  if (v.state === 'queued' || v.state === 'checking') {
    lines.push(escapeHtml(verificationLabel(v).text));
  } else {
    const signature = { valid: 'Signature valid', 'ad-hoc': 'Ad-hoc signature · no certified publisher',
      unsigned: 'Unsigned', invalid: 'Signature invalid', unavailable: 'Signature unavailable' }[v.signature] || 'Signature unavailable';
    const seal = { verified: 'Signed content verified', failed: 'Signed content verification failed', unavailable: 'Signed content not verified' }[v.seal];
    lines.push(`${signature}${seal ? ` · ${seal}` : ''}`);
    if (v.signer) lines.push(`Signer: ${escapeHtml(v.signer)}${v.teamId ? ` · Team ID: ${escapeHtml(v.teamId)}` : ''}`);
    else if (v.teamId) lines.push(`Team ID: ${escapeHtml(v.teamId)}`);
    if (v.sha256) {
      lines.push(`SHA-256: <code>${escapeHtml(v.sha256)}</code>`);
      if (v.hashChanged) lines.push('<span class="verification-status changed">File changed since first observation in this session</span>');
    }
  }
  if (v.detail) lines.push(escapeHtml(v.detail));
  if (Number.isFinite(v.checkedAt) && v.checkedAt > 0) {
    lines.push(`Checked ${escapeHtml(new Date(v.checkedAt).toLocaleString())}`);
  }
  return `<div class="verification-details">${lines.join('<br>')}</div>`;
}
