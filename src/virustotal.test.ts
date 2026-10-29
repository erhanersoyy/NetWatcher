import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractAnalysisDate } from './virustotal.js';

test('VT analysis date is separate from retrieval time; absence never becomes a fresh analysis', () => {
  assert.equal(extractAnalysisDate('last_analysis_stats:\n  malicious: 0\nlast_analysis_date: 1700000000\n'), '2023-11-14T22:13:20.000Z');
  assert.equal(extractAnalysisDate('last_analysis_stats:\n  malicious: 0'), null);
  assert.equal(extractAnalysisDate('last_analysis_date: unknown'), null);
});
