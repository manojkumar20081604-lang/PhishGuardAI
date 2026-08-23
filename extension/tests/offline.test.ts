/**
 * Phase I leftover checklist items, automated:
 *   - Popup/background scan works offline — Flask STOPPED, everything functions
 *   - Server toggle off/on switches cleanly (no errors either way)
 *
 * Premise: port 5000 must NOT be listening when this runs (verified by the
 * first test). With server mode ON, a dead backend raises
 * BackendUnavailableError which is non-retryable -> the pipeline falls back
 * to the local ONNX engine immediately. Verdicts stay correct either way.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { resolve } from 'node:path';
import { analyzeURL } from '../src/background/api';
import { __setModelBaseForTests } from '../src/ml/engine';

const FLASK_BASE = 'http://localhost:5000';
const SAFE_URL = 'https://chatgpt.com/c/6a895ec9-c214-83e8-8615-ef37e820546f';
const PHISH_URL = 'http://013224.icefactory.cl/';

const store = new Map<string, unknown>();

function stubChromeStorage(): void {
  (globalThis as Record<string, unknown>).chrome = {
    storage: {
      local: {
        get: vi.fn(async (...keys: (string | Record<string, unknown>)[]) => {
          const names = keys.map((k) => (typeof k === 'string' ? k : Object.keys(k)[0]));
          const out: Record<string, unknown> = {};
          for (const name of names) if (store.has(name)) out[name] = store.get(name);
          return out;
        }),
        set: vi.fn(async (obj: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(obj)) store.set(k, v);
        }),
      },
    },
  };
}

beforeAll(() => {
  __setModelBaseForTests(resolve(__dirname, '../public') + '/');
  stubChromeStorage();
});

afterAll(() => {
  delete (globalThis as Record<string, unknown>).chrome;
});

describe('offline operation (Flask stopped)', () => {
  it('premise: port 5000 is not listening', async () => {
    await expect(fetch(`${FLASK_BASE}/api/v1/health`)).rejects.toThrow();
  }, 15_000);

  it('server mode ON + Flask dead -> local engine answers with correct verdicts', async () => {
    store.set('pgai_server_mode', true);

    const safe = await analyzeURL(SAFE_URL);
    expect(safe.source).toBe('local');
    expect(safe.prediction).toBe('safe');

    const bad = await analyzeURL(PHISH_URL);
    expect(bad.source).toBe('local');
    expect(bad.prediction).not.toBe('safe');
  }, 90_000);

  it('server mode OFF -> instant local verdicts, no errors', async () => {
    store.set('pgai_server_mode', false);

    const result = await analyzeURL(PHISH_URL);
    expect(result.source).toBe('local');
    expect(result.prediction).not.toBe('safe');
  }, 60_000);

  it('toggle off -> on -> off switches cleanly without throwing', async () => {
    store.set('pgai_server_mode', false);
    await expect(analyzeURL(PHISH_URL)).resolves.toBeTruthy();

    store.set('pgai_server_mode', true);
    await expect(analyzeURL(PHISH_URL)).resolves.toBeTruthy();

    store.set('pgai_server_mode', false);
    const final = await analyzeURL(PHISH_URL);
    expect(final.source).toBe('local');
    expect(final.prediction).not.toBe('safe');
  }, 120_000);
});
