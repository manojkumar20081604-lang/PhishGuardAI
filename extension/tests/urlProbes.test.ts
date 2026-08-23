/**
 * Real-world false-positive regression tests (Phase I findings).
 * Runs the FULL local pipeline: brand guard -> ONNX engine -> risk fusion.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { analyzeURL } from '../src/background/api';
import { __setModelBaseForTests } from '../src/ml/engine';
import { isKnownGoodDomain } from '../src/trust/knownBrands';

beforeAll(async () => {
  __setModelBaseForTests(resolve(__dirname, '../public') + '/');
});

describe('known-brand URLs must never flag', () => {
  const cases = [
    'https://chatgpt.com/c/6a895ec9-c214-83e8-8615-ef37e820546f',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://www.notion.so/My-Notes-8f2a19d4e0b34c1f9d3e7a2b5c6d8e10',
    'https://github.com/microsoft/vscode/blob/main/README.md',
    'https://accounts.google.com/v3/Signin/challenge/pwd?continue=https%3A%2F%2Fmail.google.com',
  ];

  it.each(cases)('safe verdict for %s', async (url) => {
    expect(isKnownGoodDomain(url)).toBe(true);
    const result = await analyzeURL(url);
    expect(result.prediction).toBe('safe');
    // Consistency: score band and label must agree
    if (result.risk_score >= 61) expect(result.prediction).toBe('phishing');
    if (result.risk_score < 35) expect(result.prediction).toBe('safe');
  }, 60_000);
});

describe('real phishing still flags', () => {
  it('flags an OpenPhish sample through the full pipeline', async () => {
    const result = await analyzeURL('http://013224.icefactory.cl/');
    expect(result.prediction).not.toBe('safe');
  }, 60_000);

  it('does NOT inherit platform reputation for free-hosting subdomains', () => {
    // v3.2.1 fix: netlify.app / vercel.app removed from the brand list -
    // their subdomains are user-controlled and a major phishing-abuse vector.
    expect(isKnownGoodDomain('http://gilded-baklava-b9e48a.netlify.app/')).toBe(false);
    expect(isKnownGoodDomain('https://login-verify-secure.vercel.app/account')).toBe(false);
  });

  it('flags the golden-vector netlify phishing page through the full pipeline', async () => {
    const result = await analyzeURL('http://gilded-baklava-b9e48a.netlify.app/');
    expect(result.prediction).not.toBe('safe');
    expect(result.reasons.length).toBeGreaterThan(0);
  }, 60_000);
});
