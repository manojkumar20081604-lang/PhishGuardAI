/**
 * PDF report generator - structural guarantees.
 * The report is built with zero dependencies; these tests lock the
 * wire format so a bad release can never produce a corrupt file.
 */

import { describe, it, expect } from 'vitest';
import { buildScanReportPdf } from '../src/utils/reportPdf';
import type { ScanResult } from '../src/services/baseApi';

function decode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('latin1');
}

function sample(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    session_id: 'test',
    url: 'http://sbi-secure-verify.xyz/login',
    prediction: 'phishing',
    confidence: 0.97,
    risk_score: 92,
    risk_level: 'PHISHING',
    reasons: ['Urgency language ("blocked today")', 'Look-alike banking domain'],
    security_tips: ['Never share OTP codes'],
    summary: 'Likely phishing attempt.',
    analyzed_at: new Date('2026-08-23T08:00:00Z').toISOString(),
    ...overrides,
  };
}

describe('scan report PDF', () => {
  it('produces a structurally valid single-page PDF', () => {
    const pdf = decode(buildScanReportPdf(sample()));
    expect(pdf.startsWith('%PDF-1.4')).toBe(true);
    expect(pdf.trimEnd().endsWith('%%EOF')).toBe(true);
    expect(pdf).toContain('/Type /Catalog');
    expect(pdf).toContain('/Count 1');
    // xref offsets must all point at "N 0 obj" markers
    const xref = pdf.slice(pdf.indexOf('xref'));
    const offsets = [...xref.matchAll(/^(\d{10}) 00000 n /gm)].map((m) => Number(m[1]));
    expect(offsets.length).toBeGreaterThan(3);
    for (const offset of offsets) {
      expect(pdf.slice(offset, offset + 8)).toMatch(/^\d+ 0 obj/);
    }
  });

  it('escapes parentheses and strips non-Latin1 characters', () => {
    const pdf = decode(
      buildScanReportPdf(
        sample({
          url: 'http://test.xyz/(weird)?a=1',
          summary: 'Urgent (blocked) today 📱🚨',
        })
      )
    );
    expect(pdf).toContain('\\(weird\\)');
    expect(pdf).toContain('\\(blocked\\)');
    expect(pdf).not.toMatch(/[\u{F0}-\u{FFFF}]/u); // no stray high codepoints
    expect(pdf).not.toContain('📱');
  });

  it('paginates long content instead of overflowing one page', () => {
    const pdf = decode(
      buildScanReportPdf(
        sample({
          reasons: Array.from({ length: 60 }, (_, i) => `Risk factor number ${i + 1} with some explanatory detail`),
          tips: Array.from({ length: 40 }, (_, i) => `Tip ${i + 1}: do the sensible thing carefully`),
        })
      )
    );
    const count = Number(pdf.match(/\/Count (\d+)/)?.[1] ?? '1');
    expect(count).toBeGreaterThan(1);
  });

  it('renders safe verdicts too', () => {
    const pdf = decode(buildScanReportPdf(sample({ prediction: 'safe', risk_score: 5, confidence: 0.95 })));
    expect(pdf).toContain('(Verdict: SAFE)');
  });
});
