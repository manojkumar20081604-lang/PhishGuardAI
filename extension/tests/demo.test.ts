/**
 * Competition demo script guard (Aug 2026).
 * Every scenario here is part of the LIVE stage demo - if any of these
 * regress, the demo breaks. Run before every presentation.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { analyzeURL } from '../src/background/api';
import { scanMessage } from '../src/ml/textDetector';
import { __setModelBaseForTests } from '../src/ml/engine';

beforeAll(() => {
  __setModelBaseForTests(resolve(__dirname, '../public') + '/');
});

const OTP_SMS =
  'Dear Customer, Your account will be BLOCKED today. Unusual login detected. ' +
  'Verify your identity immediately: http://sbi-secure-verify.xyz/login ' +
  'OTP: 482913 Do not share this code with anyone. - SBI Security Team';

describe('demo script: URL scenarios', () => {
  it('step 1 - legitimate site stays green', async () => {
    const r = await analyzeURL('https://www.google.com');
    expect(r.prediction).toBe('safe');
  }, 60_000);

  it('step 2 - homoglyph clone escalates with imitation reason', async () => {
    const r = await analyzeURL('http://www.xn--80ak6aa92e.com/');
    expect(r.prediction).not.toBe('safe');
    expect(r.reasons.join(' ')).toMatch(/imitates/i);
  }, 60_000);

  it('step 3 - free-host phishing page is caught', async () => {
    const r = await analyzeURL('http://gilded-baklava-b9e48a.netlify.app/');
    expect(r.prediction).not.toBe('safe');
  }, 60_000);
});

describe('demo script: self-hosted fake login page candidates', () => {
  // Served by demo/serve.sh during the stage demo. The filename tokens are
  // deliberate: they mimic real credential-harvesting kits.
  const candidates = [
    'http://localhost:8020/paypal-secure-verify-account-login.html',
    'http://localhost:8020/paypal.com-account-security-verify-login-alert/index.html',
    'http://127.0.0.1:8020/paypal-verify-login.html',
  ];

  it.each(candidates)('flags %j', async (url) => {
    const r = await analyzeURL(url);
    console.log(`[demo-candidate] ${url} -> ${r.prediction} (${Math.round(r.risk_score)}) :: ${r.reasons.join(' | ')}`);
    expect(r.prediction).not.toBe('safe');
  }, 60_000);
});

describe('demo script: message scenarios', () => {
  it('step 4 - OTP scam SMS is flagged', async () => {
    const r = await scanMessage(OTP_SMS);
    expect(r.prediction).toBe('phishing');
  }, 60_000);

  it('control - normal message stays clean', async () => {
    const r = await scanMessage(
      'Hi, lunch tomorrow at 1pm at the usual place? Bring the project notes. - Priya'
    );
    expect(r.prediction).toBe('safe');
  }, 60_000);
});
