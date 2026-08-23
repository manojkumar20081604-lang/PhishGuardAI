/**
 * Homoglyph / punycode detector tests (v3.2).
 * FP-safety matters as much as detection: legitimate IDNs must stay clean.
 */

import { describe, it, expect } from 'vitest';
import { inspectHomoglyph, punycodeDecode } from '../src/security/homoglyph';

describe('punycode decoder', () => {
  it('decodes RFC 3492 reference strings', () => {
    expect(punycodeDecode('bcher-kva')).toBe('bücher');
    // The famous Apple homograph: xn--80ak6aa92e displays as "аррӏе"
    // (Cyrillic а,р + Cyrillic ӏ + Latin е) - verified via Python idna codec
    const decoded = punycodeDecode('80ak6aa92e') ?? '';
    expect(decoded).toBe('аррӏе');
    expect(/[\u0400-\u04FF]/.test(decoded)).toBe(true);
  });

  it('rejects malformed input gracefully', () => {
    expect(punycodeDecode('!!!')).toBeNull();
  });
});

describe('homoglyph inspection', () => {
  it('flags Cyrillic look-alike of a known brand as brand imitation', () => {
    const report = inspectHomoglyph('https://аpple.com/login'); // 'а' is Cyrillic
    expect(report.brandImitation).toBe('apple.com');
    expect(report.escalate).toBe(true);
    expect(report.reasons.join(' ')).toMatch(/mixes Latin with Cyrillic|imitates/i);
  });

  it('flags FULL-punycode brand clones (wildfire case: xn--80ak6aa92e)', () => {
    // Regression: the entire label is punycode, so there is no mixed-script
    // signal - only confusable folding + exact brand match can catch this.
    const report = inspectHomoglyph('http://www.xn--80ak6aa92e.com/');
    expect(report.brandImitation).toBe('apple.com');
    expect(report.escalate).toBe(true);
    expect(report.reasons.join(' ')).toMatch(/imitates/i);
  });

  it('flags invisible characters as a hard signal', () => {
    const report = inspectHomoglyph('https://pay\u200Bpal.com');
    expect(report.escalate).toBe(true);
    expect(report.reasons.join(' ')).toMatch(/invisible/i);
  });

  it('does NOT flag the genuine brand', () => {
    const report = inspectHomoglyph('https://www.apple.com/iphone/');
    expect(report.escalate).toBe(false);
    expect(report.brandImitation).toBeNull();
    expect(report.reasons).toHaveLength(0);
  });

  it('leaves legitimate internationalized domains alone', () => {
    // Each label is pure Japanese (例えテスト) - no Latin mixing, no brand match.
    // Verified: 例=xn--fsq, え=xn--r8j, テ=xn--ddk, ス=xn--zck, ト=xn--fdk
    const report = inspectHomoglyph('https://xn--fsq.xn--r8j.xn--ddk.test/path');
    expect(report.escalate).toBe(false);
    expect(report.brandImitation).toBeNull();
  });

  it('treats ordinary ASCII domains as clean', () => {
    for (const url of [
      'https://chatgpt.com/c/6a895ec9-c214-83e8-8615-ef37e820546f',
      'http://013224.icefactory.cl/',
      'https://github.com/microsoft/vscode/blob/main/README.md',
    ]) {
      const report = inspectHomoglyph(url);
      expect(report.escalate).toBe(false);
      expect(report.brandImitation).toBeNull();
      expect(report.reasons).toHaveLength(0);
    }
  });
});
