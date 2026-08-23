/**
 * Golden parity tests: the browser-side engine must reproduce the Flask
 * backend's decisions on real held-out URLs (backend/tests/data/golden_urls.json).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { extractUrlFeatures, FEATURE_NAMES } from '../src/ml/features';
import { predictUrl, __setModelBaseForTests } from '../src/ml/engine';

interface GoldenEntry {
  url: string;
  label: string;
  features: number[];
  p_phishing: number;
  expected: { prediction: string; confidence: number };
}

const golden: GoldenEntry[] = JSON.parse(
  readFileSync(
    resolve(__dirname, '../../backend/tests/data/golden_urls.json'),
    'utf-8'
  )
);

describe('feature extractor parity', () => {
  it('matches Python-extracted features on every golden vector', () => {
    let worst = 0;
    for (const g of golden) {
      const got = Array.from(extractUrlFeatures(g.url));
      for (let i = 0; i < FEATURE_NAMES.length; i++) {
        const d = Math.abs(got[i] - g.features[i]);
        if (d > worst) worst = d;
        expect(d, `${FEATURE_NAMES[i]} drift on ${g.url}`).toBeLessThan(1e-4);
      }
    }
    console.log(`features: max abs drift across ${golden.length} URLs = ${worst.toExponential(2)}`);
  });
});

describe('model decision parity', () => {
  beforeAll(async () => {
    __setModelBaseForTests(resolve(__dirname, '../public') + '/');
    await import('../src/ml/engine').then((m) => m.loadModel());
  });

  it(
    'reproduces p(phishing) within tolerance and identical verdicts',
    async () => {
      let maxProbDrift = 0;
      let mismatches = 0;

      for (const g of golden) {
        const { prediction, confidence } = await predictUrl(g.url);
        const pGot = prediction === 'safe' ? 1 - confidence : confidence;
        maxProbDrift = Math.max(maxProbDrift, Math.abs(pGot - g.p_phishing));
        if (prediction !== g.expected.prediction) mismatches++;
        expect(prediction).toBe(g.expected.prediction);
      }

      console.log(
        `decisions: ${golden.length - mismatches}/${golden.length} exact | ` +
          `max prob drift = ${maxProbDrift.toFixed(6)}`
      );
      expect(mismatches).toBe(0);
      expect(maxProbDrift).toBeLessThan(5e-3);
    },
    120_000
  );

  it('flags real phishing samples as not-safe at high rate', async () => {
    const phish = golden.filter((g) => g.label === 'phishing');
    let flagged = 0;
    for (const g of phish) {
      const { prediction } = await predictUrl(g.url);
      if (prediction !== 'safe') flagged++;
    }
    console.log(`recall-style check: ${flagged}/${phish.length} phishing flagged`);
    expect(flagged / phish.length).toBeGreaterThan(0.85);
  });
});
