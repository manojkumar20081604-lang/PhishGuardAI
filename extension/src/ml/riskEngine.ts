/**
 * PhishGuard AI - Risk Engine (offline port)
 *
 * TypeScript port of backend/services/risk_engine.py. Offline the threat-intel
 * and domain-reputation components score 0, exactly as the Python engine does
 * when no intel data is provided.
 */

import type { Prediction } from './engine';

const WEIGHTS = {
  ml_prediction: 0.35,
  threat_intel: 0.3,
  heuristics: 0.2,
  domain_reputation: 0.15,
} as const;

export interface RiskResult {
  risk_score: number;
  risk_level: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
  risk_color: string;
  breakdown: Record<string, number>;
  recommendation: string;
}

export function calculateRiskScore(
  prediction: Prediction,
  confidence: number,
  reasons: string[] = [],
  domainInfo: { age_days?: number; risk_factors?: string[] } = {},
  urlIndicators: { risk_score?: number; brand_mentions?: string[] } = {}
): RiskResult {
  const mlScore = calculateMlScore(prediction, confidence);
  const tiScore = 0; // offline: no intel feeds
  const heuristicScore = calculateHeuristicScore(reasons);
  const domainScore = calculateDomainScore(domainInfo, urlIndicators);

  const riskScore = Math.trunc(
    mlScore * WEIGHTS.ml_prediction +
      tiScore * WEIGHTS.threat_intel +
      heuristicScore * WEIGHTS.heuristics +
      domainScore * WEIGHTS.domain_reputation
  );

  let riskLevel: RiskResult['risk_level'];
  let riskColor: string;
  if (riskScore >= 61) {
    riskLevel = 'PHISHING';
    riskColor = '#ef4444';
  } else if (riskScore >= 31) {
    riskLevel = 'SUSPICIOUS';
    riskColor = '#f59e0b';
  } else {
    riskLevel = 'SAFE';
    riskColor = '#10b981';
  }

  return {
    risk_score: riskScore,
    risk_level: riskLevel,
    risk_color: riskColor,
    breakdown: {
      ml_score: mlScore,
      threat_intel_score: tiScore,
      heuristic_score: heuristicScore,
      domain_score: domainScore,
    },
    recommendation: getRecommendation(riskLevel),
  };
}

function calculateMlScore(prediction: Prediction, confidence: number): number {
  if (prediction === 'phishing') return Math.min(confidence * 100 + 20, 100) | 0;
  if (prediction === 'suspicious') return (confidence * 60 + 20) | 0;
  return ((1 - confidence) * 30) | 0;
}

function calculateHeuristicScore(reasons: string[]): number {
  const HIGH = ['contains @ symbol', 'uses ip address', 'very long url', 'login page', 'credential harvesting', 'fake login'];
  const MEDIUM = ['no https', 'suspicious tld', 'unusual domain', 'multiple redirects'];

  let score = 0;
  for (const reasonRaw of reasons) {
    const reason = reasonRaw.toLowerCase();
    let matched = false;

    for (const hr of HIGH) {
      if (reason.includes(hr)) {
        score += 15;
        matched = true;
        break;
      }
    }
    if (!matched) {
      for (const mr of MEDIUM) {
        if (reason.includes(mr)) {
          score += 8;
          break;
        }
      }
    }
  }
  return Math.min(score, 100);
}

function calculateDomainScore(
  domainInfo: { age_days?: number; risk_factors?: string[] },
  urlIndicators: { risk_score?: number; brand_mentions?: string[] }
): number {
  let score = 0;

  const ageDays = domainInfo.age_days;
  if (ageDays !== undefined && ageDays !== null) {
    if (ageDays < 7) score += 30;
    else if (ageDays < 30) score += 15;
    else if (ageDays > 365) score -= 10;
  }

  score += (domainInfo.risk_factors?.length ?? 0) * 8;
  score += Math.min(urlIndicators.risk_score ?? 0, 20);
  score += (urlIndicators.brand_mentions?.length ?? 0) * 10;

  return Math.max(0, Math.min(score, 100));
}

function getRecommendation(riskLevel: RiskResult['risk_level']): string {
  const recommendations: Record<RiskResult['risk_level'], string[]> = {
    PHISHING: [
      'DO NOT visit this URL',
      'DO NOT enter any personal information',
      'Report to your IT security team',
    ],
    SUSPICIOUS: [
      'Exercise caution before visiting',
      'Verify the sender through official channels',
      'Do not enter credentials unless you typed the address yourself',
    ],
    SAFE: [
      'No major red flags detected',
      'Always verify addresses before entering sensitive information',
    ],
  };
  return recommendations[riskLevel][0];
}
