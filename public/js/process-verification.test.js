import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verificationLabel, renderVerificationBadge, renderVerificationDetails } from './process-verification.js';

test('verification badges distinguish evidence states without a verify button', () => {
  for (const [signature, text] of [['valid', 'Signature valid'], ['ad-hoc', 'Ad-hoc signature'], ['unsigned', 'Unsigned'], ['invalid', 'Signature invalid'], ['unavailable', 'Verification unavailable']]) {
    assert.equal(verificationLabel({ state: 'complete', signature }).text, text);
  }
  assert.equal(verificationLabel({ state: 'checking', signature: 'valid' }).text, 'Checking signature…');
  assert.equal(verificationLabel({ state: 'complete', signature: 'valid', hashChanged: true }).text, 'Executable changed');
  assert.equal(verificationLabel({ state: 'complete', signature: 'invalid', hashChanged: true }).text, 'Signature invalid');
  assert.doesNotMatch(renderVerificationBadge(null), /button|safe|trusted/i);
});

test('signature metadata and diagnostics are escaped; hashes are observations, not a trusted baseline', () => {
  const html = renderVerificationDetails({ state: 'complete', signature: 'valid', seal: 'verified',
    signer: '<img src=x onerror=alert(1)>', teamId: '<TEAM>', sha256: '<HASH>',
    detail: '<script>alert(1)</script>', hashChanged: true, checkedAt: 1 });
  assert.doesNotMatch(html, /<img|<script|<TEAM>|<HASH>|trusted|safe/i);
  assert.match(html, /&lt;img/); assert.match(html, /Signed content verified/);
  assert.match(html, /File changed since first observation/);
  assert.match(html, /On-disk executable/);
});
