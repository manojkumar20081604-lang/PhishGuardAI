/**
 * PhishGuard AI - Scan API Client
 *
 * Main analysis endpoints:
 *   POST /api/v1/analyze/url       - Analyze a URL (ML + risk engine + XAI)
 *   GET  /api/v1/scans/{session_id} - Fetch a stored result by session ID
 */

import { BaseApiClient, ScanResult } from './baseApi';

interface AnalyzeUrlResponse {
  success: boolean;
  session_id?: string;
  analysis_id?: number;
  url: string;
  prediction: string;
  confidence: number;
  risk_score: number;
  risk_level: string;
  risk_breakdown?: Record<string, number>;
  reasons?: string[];
  summary?: string;
  security_tips?: string[];
  recommendation?: string;
  analyzed_at: string;
}

interface ScanBySessionResponse {
  session_id: string;
  scan_type: string;
  risk_score: number;
  risk_level: string;
  input_url: string | null;
  explanation_text: string | null;
  features_json: Record<string, unknown>;
  created_at: string | null;
}

export class ScanApiClient extends BaseApiClient {
  /**
   * Analyze a URL for phishing risk.
   */
  async analyze(url: string): Promise<ScanResult> {
    const raw = await this.post<AnalyzeUrlResponse>('/api/v1/analyze/url', { url });
    return normalizeAnalyzeResponse(raw);
  }

  /**
   * Fetch a previously stored scan result by session ID.
   * Note: user-scoped scan history is deferred until auth is implemented.
   */
  async getBySession(sessionId: string): Promise<ScanResult> {
    const raw = await this.get<ScanBySessionResponse>(
      `/api/v1/scans/${encodeURIComponent(sessionId)}`
    );

    return {
      session_id: raw.session_id,
      url: raw.input_url ?? '',
      prediction: normalizePrediction(raw.risk_level),
      confidence: raw.risk_score,
      risk_score: Math.round((raw.risk_score ?? 0) * 100) / 100,
      risk_level: raw.risk_level,
      summary: raw.explanation_text ?? undefined,
      features: raw.features_json,
      analyzed_at: raw.created_at ?? new Date().toISOString(),
    };
  }
}

function normalizeAnalyzeResponse(raw: AnalyzeUrlResponse): ScanResult {
  return {
    session_id: raw.session_id,
    analysis_id: raw.analysis_id,
    url: raw.url,
    prediction: normalizePrediction(raw.prediction),
    confidence: raw.confidence,
    risk_score: raw.risk_score,
    risk_level: raw.risk_level,
    risk_breakdown: raw.risk_breakdown,
    reasons: raw.reasons,
    summary: raw.summary,
    security_tips: raw.security_tips,
    recommendation: raw.recommendation,
    analyzed_at: raw.analyzed_at,
  };
}

export function normalizePrediction(value: string): 'safe' | 'suspicious' | 'phishing' {
  const v = String(value || '').toLowerCase();
  if (v.includes('phish') || v.includes('critical') || v.includes('high')) return 'phishing';
  if (v.includes('suspicious') || v.includes('medium')) return 'suspicious';
  return 'safe';
}

export const scanApi = new ScanApiClient();
