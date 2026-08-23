/**
 * Phase H functional checks: offline email/SMS rule engines + URL escalation.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanMessage, detectMessageType } from '../src/ml/textDetector';
import { __setModelBaseForTests, loadModel } from '../src/ml/engine';

const golden: Array<{ url: string; label: string }> = JSON.parse(
  readFileSync(resolve(__dirname, '../../backend/tests/data/golden_urls.json'), 'utf-8')
);

describe('message type detection', () => {
  it('classifies headers as email and short texts as SMS', () => {
    expect(detectMessageType('From: boss@corp.com\nSubject: Report\n\nPlease review.')).toBe('email');
    expect(detectMessageType('Your OTP is 4821. Do not share.')).toBe('sms');
  });
});

describe('scam detection', () => {
  it('flags an OTP/bank-account scam SMS as phishing', async () => {
    const result = await scanMessage(
      'URGENT! Your bank account has been suspended. Confirm identity now at http://secure-login-verify-apple-id.example-top.xyz/account or your card will be blocked. OTP required.'
    );
    expect(result.prediction).toBe('phishing');
    console.log(`scam SMS score=${result.risk_score} reasons=${result.reasons.length}`);
  });

  it('treats casual conversation as safe', async () => {
    const result = await scanMessage('hey! lunch tomorrow at 1pm? bring the book you mentioned');
    expect(result.prediction).toBe('safe');
  });

  it('escalates when an embedded link is confirmed dangerous by the URL AI', async () => {
    __setModelBaseForTests(resolve(__dirname, '../public') + '/');
    await loadModel();

    const badUrl = golden.find((g) => g.label === 'phishing')!.url;
    const result = await scanMessage(
      `Congratulations! You won a prize. Claim your reward now: ${badUrl}`
    );
    expect(result.prediction).toBe('phishing');
    expect(result.reasons.join(' ')).toMatch(/URL AI|prize|reward/i);
  }, 60_000);
});
