/**
 * Background Service - Local-First Analysis Engine
 *
 * Analysis pipeline (per plan v3.1):
 *   trust check -> local cache -> LOCAL ONNX engine -> optional backend enrichment
 *
 * The Flask backend is an enhancement, not a requirement: the extension is
 * fully functional offline.
 */

import { predictUrl } from '../ml/engine';
import { explainUrl } from '../ml/explainer';
import { calculateRiskScore } from '../ml/riskEngine';
import { extractUrlFeatures } from '../ml/features';
import type { ScanResult } from '../services/baseApi';
import {
  ScanApiClient,
  MetricsApiClient,
  ModelApiClient,
  ThreatIntelApiClient,
  DEFAULT_BASE_URL,
} from '../services';
import { set, get, clear as cacheClear, list as cacheList, isDbReady, ScanCache } from '../db/cache';
import { checkTrust, getLists, addTo, removeFrom } from '../trust/lists';
import { isKnownGoodDomain } from '../trust/knownBrands';
import { inspectHomoglyph } from '../security/homoglyph';
import { recordVerdict, getStats, resetStats } from '../stats/counter';

const API_BASE_URL = DEFAULT_BASE_URL; // optional Flask backend
const SERVER_MODE_KEY = 'pgai_server_mode'; // chrome.storage flag

// ============================================================================
// INITIALIZATION
// ============================================================================

export async function initBackgroundAPIs(): Promise<boolean> {
  console.log('[Background] Initializing local-first analysis engine');
  const ready = await isDbReady();
  // Pre-warm the ONNX session so first scan is fast
  try {
    const { loadModel } = await import('../ml/engine');
    await loadModel();
    console.log('[Background] ONNX model loaded');
  } catch (error) {
    console.error('[Background] Model preload failed (will retry on demand):', error);
  }
  console.log('[Background] Background APIs initialized, dbReady:', ready);
  return ready;
}

export async function isServerModeEnabled(): Promise<boolean> {
  try {
    const stored = await chrome.storage.local.get(SERVER_MODE_KEY);
    return Boolean(stored[SERVER_MODE_KEY]);
  } catch {
    return false;
  }
}

// ============================================================================
// ANALYSIS (local-first)
// ============================================================================

export async function analyzeURL(url: string): Promise<ScanResult & { isCached?: boolean }> {
  console.log('[Background] Analyzing URL:', url);

  // 0. Trust lists override everything (Phase D)
  const trust = await checkTrust(url);
  if (trust === 'blocked') {
    console.log('[Background] Blocked by user trust list');
    const blocked = trustOverrideResult(url, true);
    void recordVerdict(blocked);
    return blocked;
  }
  if (trust === 'trusted') {
    console.log('[Background] Trusted by user trust list');
    return trustOverrideResult(url, false); // not counted as a scan
  }

  // 1. Server mode: backend first (richer intel), fall through on failure
  if (await isServerModeEnabled()) {
    try {
      const scanClient = new ScanApiClient(API_BASE_URL);
      const result = await scanClient.analyze(url);
      await cacheResult(url, result);
      void recordVerdict(result);
      console.log('[Background] Analysis via backend:', result.prediction);
      return result;
    } catch (error) {
      console.warn('[Background] Server analysis failed, using local engine:', error);
    }
  }

  // 2. Cache hit -> instant answer
  const cached = await getCachedScan(url);
  if (cached) {
    console.log('[Background] Cached result');
    return cacheToScanResult(cached);
  }

  // 3. Local ONNX engine (fully offline)
  const result = await analyzeLocally(url);
  await cacheResult(url, result);
  void recordVerdict(result);
  console.log('[Background] Local analysis complete:', result.prediction);
  return result;
}

async function analyzeLocally(url: string): Promise<ScanResult & { source?: string }> {
  const features = extractUrlFeatures(url);
  const featureFlags = {
    has_https: features[1] === 1,
    has_ip_address: features[3] === 1,
    dash_count: features[4],
    suspicious_tld: features[8] === 1,
  };

  // Raw ML verdict
  let { prediction, confidence } = await predictUrl(url);

  // Known-brand prior: major domains never flag on string heuristics alone.
  // (Look-alike domains like `chatgpt-secure.xyz` do NOT match - still scanned.)
  if (prediction !== 'safe' && isKnownGoodDomain(url)) {
    console.log('[Background] Known-good brand domain, downgrading ML verdict');
    confidence = Math.max(0.9, 1 - confidence);
    prediction = 'safe';
  }

  // Homoglyph / punycode inspection (v3.2): look-alike domain scams.
  // Hard signals (brand imitation, invisible chars) force at least SUSPICIOUS;
  // softer signals only add explanatory reasons below.
  const homoglyph = inspectHomoglyph(url);
  if (homoglyph.escalate && prediction === 'safe') {
    console.log('[Background] Homoglyph hard signal, escalating verdict');
    prediction = 'suspicious';
    confidence = Math.max(confidence, 0.85);
  }

  const explanation = explainUrl(url, prediction, featureFlags);
  if (homoglyph.reasons.length > 0) {
    explanation.risk_indicators = [
      ...explanation.risk_indicators,
      ...homoglyph.reasons,
    ];
  }
  const risk = calculateRiskScore(prediction, confidence, explanation.risk_indicators);

  // SINGLE SOURCE OF TRUTH: the fused risk engine decides both score AND label,
  // so the UI can never show "35 = Phishing" style contradictions.
  const fusedPrediction =
    risk.risk_level === 'PHISHING' ? 'phishing'
    : risk.risk_level === 'SUSPICIOUS' ? 'suspicious'
    : 'safe';

  return {
    session_id: `local-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    url,
    prediction: fusedPrediction,
    confidence,
    risk_score: risk.risk_score,
    risk_level: risk.risk_level,
    risk_breakdown: risk.breakdown,
    reasons: explanation.risk_indicators,
    summary: explanation.summary,
    security_tips: explanation.security_tips,
    recommendation: risk.recommendation,
    analyzed_at: new Date().toISOString(),
    source: 'local',
  };
}

function cacheToScanResult(cached: ScanCache): ScanResult & { isCached?: boolean } {
  return {
    session_id: cached.session_id,
    url: cached.url,
    prediction: cached.prediction,
    confidence: cached.risk_score / 100,
    risk_score: cached.risk_score,
    risk_level: String(cached.prediction),
    summary: cached.summary,
    analyzed_at: new Date(cached.timestamp).toISOString(),
    isCached: true,
  };
}

/** Get cached analysis result for offline fallback. */
export async function getCachedScan(url: string): Promise<ScanCache | null> {
  try {
    const cached = await get(url);
    if (cached) {
      return { ...cached, isCached: true } as ScanCache & { isCached: true };
    }
    return null;
  } catch (error) {
    console.error('[Background] Cache read failed:', error);
    return null;
  }
}

/** List recent scans from local cache. */
export async function listRecentScans(limit: number = 5): Promise<ScanCache[]> {
  try {
    return await cacheList(limit);
  } catch (error) {
    console.error('[Background] Cache list failed:', error);
    return [];
  }
}

function trustOverrideResult(url: string, blocked: boolean): ScanResult & { source?: string } {
  return {
    session_id: `trust-${Date.now().toString(36)}`,
    url,
    prediction: blocked ? 'phishing' : 'safe',
    confidence: 1,
    risk_score: blocked ? 100 : 0,
    risk_level: blocked ? 'PHISHING' : 'SAFE',
    risk_breakdown: { trust_list: blocked ? 100 : 0 },
    reasons: [blocked ? 'Domain is on your block list' : 'Domain is on your trusted list'],
    summary: blocked
      ? 'You explicitly blocked this domain. PhishGuard will always flag it.'
      : 'You marked this domain as trusted. PhishGuard will not analyze it.',
    recommendation: blocked
      ? 'Remove it from your block list in Settings if this was a mistake'
      : '',
    analyzed_at: new Date().toISOString(),
    source: 'trust-list',
  };
}

async function cacheResult(url: string, result: ScanResult): Promise<void> {
  try {
    await set(url, {
      session_id: result.session_id,
      url: result.url || url,
      risk_score: result.risk_score,
      prediction: result.prediction,
      summary: typeof result.summary === 'string' ? result.summary : undefined,
    });
    console.log('[Background] Result cached:', url);
  } catch (error) {
    console.error('[Background] Cache write failed:', error);
  }
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

export async function clearAllCache(): Promise<void> {
  try {
    await cacheClear();
    console.log('[Background] Cache cleared');
  } catch (error) {
    console.error('[Background] Clear cache failed:', error);
  }
}

// ============================================================================
// HEALTH & METRICS
// ============================================================================

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const metricsClient = new MetricsApiClient(API_BASE_URL);
    return await metricsClient.isBackendAvailable();
  } catch (error) {
    console.error('[Background] Health check failed:', error);
    return false;
  }
}

export async function getMetricsOverview() {
  try {
    const metricsClient = new MetricsApiClient(API_BASE_URL);
    return await metricsClient.getOverview();
  } catch (error) {
    console.error('[Background] Get overview failed:', error);
    return null;
  }
}

export async function getModelVersions(modelType: string) {
  try {
    const modelClient = new ModelApiClient(API_BASE_URL);
    return await modelClient.listVersions(modelType);
  } catch (error) {
    console.error('[Background] Get model versions failed:', error);
    return [];
  }
}

// ============================================================================
// THREAT INTELLIGENCE
// ============================================================================

export async function checkThreatIntel(sourceType: string, identifier: string) {
  try {
    const threatClient = new ThreatIntelApiClient(API_BASE_URL);
    return await threatClient.checkThreatIntel(sourceType, identifier);
  } catch (error) {
    console.error('[Background] Threat intel check failed:', error);
    return null;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

// ============================================================================
// TRUST LISTS API (Phase D)
// ============================================================================

export async function getTrustLists() {
  return getLists();
}

export async function addTrustEntry(list: 'trusted' | 'blocked', domain: string) {
  return addTo(list, domain);
}

export async function removeTrustEntry(list: 'trusted' | 'blocked', domain: string) {
  return removeFrom(list, domain);
}

// ============================================================================
// STATS API (Phase G)
// ============================================================================

export function getVerdictStats() {
  return getStats();
}

export function resetVerdictStats() {
  return resetStats();
}

export function getAPIs() {
  return {
    analyzeURL,
    getCachedScan,
    listRecentScans,
    clearAllCache,
    checkBackendHealth,
    getMetricsOverview,
    getModelVersions,
    checkThreatIntel,
    getTrustLists,
    addTrustEntry,
    removeTrustEntry,
  };
}
