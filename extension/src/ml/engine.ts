/**
 * PhishGuard AI - Local ONNX Inference Engine
 *
 * Loads the bundled url-model-v1.onnx via onnxruntime and applies the
 * same decision thresholds as the Flask backend (ml_service.py):
 *   p(phishing) >= 0.65 -> 'phishing'
 *   p(phishing) >= 0.35 -> 'suspicious'
 *   else                -> 'safe'  (confidence = 1 - p)
 *
 * Runtime selection:
 *   - Extension (Chrome/Firefox): onnxruntime-web/wasm (lazy, code-split)
 *   - Node (vitest parity tests): onnxruntime-node
 */

import { extractUrlFeatures, FEATURE_NAMES } from './features';

export type Prediction = 'safe' | 'suspicious' | 'phishing';

interface SimpleSession {
  inputNames: readonly string[];
  outputNames: readonly string[];
  run(feeds: Record<string, { data: Float32Array }>): Promise<Record<string, { data: Float32Array }>>;
}

interface OrtLike {
  Tensor: new (type: string, data: Float32Array, dims: number[]) => { data: Float32Array };
  InferenceSession: {
    create(path: string, opts?: Record<string, unknown>): Promise<SimpleSession>;
  };
  env?: {
    wasm: { numThreads: number; wasmPaths?: string };
  };
}

interface SessionHandle {
  session: SimpleSession;
  ort: OrtLike;
}

const THRESHOLDS = { phishing: 0.65, suspicious: 0.35 };
const MODEL_FILE = 'models/url-model-v3.onnx';
/** Bump when MODEL_FILE changes - stale cache entries are auto-invalidated. */
export const MODEL_VERSION = 'v3';

let sessionPromise: Promise<SessionHandle> | null = null;
let modelBaseOverride: string | null = null;

function modelBaseUrl(): string {
  if (modelBaseOverride !== null) return modelBaseOverride;
  if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
    return chrome.runtime.getURL('');
  }
  return '/'; // non-extension context
}

function isNodeRuntime(): boolean {
  // Explicit node check - do NOT key off the chrome global, so tests may
  // stub chrome.storage without flipping the engine into wasm/browser mode.
  return typeof process !== 'undefined' && !!process.versions?.node;
}

/** Test hook: point the loader at a filesystem/CDN base instead of extension URLs. */
export function __setModelBaseForTests(base: string | null): void {
  modelBaseOverride = base;
  sessionPromise = null; // force reload with new base
}

async function loadSession(): Promise<SessionHandle> {
  const useNode = isNodeRuntime();
  let ort: OrtLike;
  let executionProviders: string[];

  if (useNode) {
    ort = (await import('onnxruntime-node')) as unknown as OrtLike;
    executionProviders = ['cpu'];
  } else {
    // Lazy dynamic import keeps the ~70KB ORT wrapper out of the main chunks,
    // and lets Vite code-split it away from popup/content entry points.
    ort = (await import('onnxruntime-web/wasm')) as unknown as OrtLike;
    ort.env!.wasm.numThreads = 1; // MV3 service workers: no nested workers
    ort.env!.wasm.wasmPaths = `${modelBaseUrl()}vendor/ort/`;
    executionProviders = ['wasm'];
  }

  const session = await ort.InferenceSession.create(`${modelBaseUrl()}${MODEL_FILE}`, {
    executionProviders,
    graphOptimizationLevel: 'all',
  });
  return { session, ort };
}

export async function loadModel(): Promise<void> {
  sessionPromise ??= loadSession();
  await sessionPromise;
}

/** Raw probability that the URL is phishing (0..1). */
export async function predictUrlProbability(url: string): Promise<number> {
  const { session, ort } = await (sessionPromise ??= loadSession());
  const inputName = session.inputNames[0] ?? 'float_input';
  const feeds: Record<string, { data: Float32Array }> = {
    [inputName]: new ort.Tensor('float32', extractUrlFeatures(url), [1, FEATURE_NAMES.length]),
  };
  const results = await session.run(feeds);

  // Output is either [n,2] probabilities or [n] single-column depending on export
  const probaName =
    Object.keys(results).find((k) => k.toLowerCase().includes('prob')) ??
    Object.keys(results)[Object.keys(results).length - 1];
  const data = results[probaName].data;
  return data.length === 2 ? data[1] : data[0];
}

/** Full decision identical to ml_service.predict_url. */
export async function predictUrl(
  url: string
): Promise<{ prediction: Prediction; confidence: number }> {
  const p = await predictUrlProbability(url);
  if (p >= THRESHOLDS.phishing) return { prediction: 'phishing', confidence: round(p) };
  if (p >= THRESHOLDS.suspicious) return { prediction: 'suspicious', confidence: round(p) };
  return { prediction: 'safe', confidence: round(1 - p) };
}

function round(v: number): number {
  return Math.round(v * 1000) / 1000;
}
