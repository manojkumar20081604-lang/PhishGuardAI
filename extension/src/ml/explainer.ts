/**
 * PhishGuard AI - Explainer (offline port)
 *
 * TypeScript port of the URL branch of backend/services/explainer.py:
 * pattern checks -> risk/safe indicators + summary + security tips.
 */

import type { Prediction } from './engine';

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.club', '.work', '.date'];
const SAFE_DOMAINS = ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'apple.com', 'paypal.com'];
const ESTABLISHED_TLDS = ['com', 'org', 'net', 'edu', 'gov', 'co'];

export interface Explanation {
  prediction: Prediction;
  explanations: Array<{ pattern: string; risk: string; explanation: string; evidence: string }>;
  risk_indicators: string[];
  safe_indicators: string[];
  summary: string;
  security_tips: string[];
}

function pyNetloc(url: string): { netloc: string; domain: string } {
  let rest = url;
  const schemeIdx = rest.indexOf('://');
  if (schemeIdx !== -1) rest = rest.slice(schemeIdx + 3);
  const slashIdx = rest.indexOf('/');
  if (slashIdx !== -1) rest = rest.slice(0, slashIdx);
  const qIdx = rest.search(/[?#]/);
  if (qIdx !== -1) rest = rest.slice(0, qIdx);
  return { netloc: rest.toLowerCase(), domain: rest.toLowerCase() };
}

export function explainUrl(
  url: string,
  prediction: Prediction,
  features?: {
    has_https?: boolean;
    has_ip_address?: boolean;
    dash_count?: number;
    suspicious_tld?: boolean;
  }
): Explanation {
  const explanations: Explanation['explanations'] = [];
  const riskIndicators: string[] = [];
  const safeIndicators: string[] = [];
  const lower = url.toLowerCase();
  const { netloc, domain } = pyNetloc(url);

  // ip_address
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
    explanations.push({
      pattern: 'ip_address',
      risk: 'HIGH',
      explanation: 'Using an IP address instead of a domain name is a common phishing tactic',
      evidence: 'IP address found in URL',
    });
    riskIndicators.push('ip address');
  }

  // @ symbol
  if (url.includes('@')) {
    explanations.push({
      pattern: 'at_symbol',
      risk: 'HIGH',
      explanation: 'The @ symbol can hide the real destination domain',
      evidence: '@ symbol found in URL',
    });
    riskIndicators.push('contains @ symbol');
  }

  // url_length
  if (url.length > 150) {
    explanations.push({
      pattern: 'url_length',
      risk: 'MEDIUM',
      explanation: 'Very long URLs are used to obfuscate the true destination',
      evidence: `URL length: ${url.length} characters`,
    });
    riskIndicators.push(`Long URL (${url.length} chars)`);
  } else if (url.length <= 150) {
    safeIndicators.push(`URL length: ${url.length}`);
  }

  // double_extension
  if (/\.[a-z]{2,4}\.[a-z]{2,4}$/.test(lower)) {
    explanations.push({
      pattern: 'double_extension',
      risk: 'HIGH',
      explanation: 'Double file extensions are often used to disguise executables',
      evidence: `Extension chain: ${lower.split('.').slice(-2).join('.')}`,
    });
    riskIndicators.push('double extension');
  }

  // suspicious_tld
  if (SUSPICIOUS_TLDS.some((t) => lower.endsWith(t))) {
    const tld = url.split('.').pop() ?? '';
    explanations.push({
      pattern: 'suspicious_tld',
      risk: 'MEDIUM',
      explanation: 'This top-level domain is frequently abused for phishing campaigns',
      evidence: `TLD: .${tld}`,
    });
    riskIndicators.push(`Suspicious TLD: .${tld}`);
  }

  // encoded_chars
  if (/%[0-9a-f]{2}/i.test(url)) {
    explanations.push({
      pattern: 'encoded_chars',
      risk: 'LOW',
      explanation: 'Encoded characters can be used to bypass filters',
      evidence: 'Percent-encoded characters found',
    });
  }

  // subdomain_abuse
  const strippedDomain = domain.replace(/^secure\./, '').replace(/^login\./, '');
  const hasKeyword = /\b(secure|login|account|verify)\b/.test(domain) ||
    /^secure\.|^login\.|^account\.|^verify\./.test(netloc);
  if (hasKeyword && !SAFE_DOMAINS.some((s) => domain.includes(s))) {
    explanations.push({
      pattern: 'subdomain_abuse',
      risk: 'HIGH',
      explanation: 'Suspicious keywords in subdomain can impersonate legitimate sites',
      evidence: `Subdomain contains: ${strippedDomain}`,
    });
    riskIndicators.push('Suspicious subdomain keywords');
  }

  // Safe indicators
  if (url.startsWith('https')) safeIndicators.push('HTTPS encryption present');
  const parts = netloc.split('.');
  const mainDomain = parts.length > 1 ? parts[parts.length - 2] : netloc;
  if (ESTABLISHED_TLDS.includes(mainDomain)) {
    safeIndicators.push('Established TLD (.com, .org, etc.)');
  }

  // Feature-based indicators
  if (features?.has_https === false) riskIndicators.push('No HTTPS encryption');
  if (features?.has_ip_address) riskIndicators.push('Contains IP address');
  if ((features?.dash_count ?? 0) > 3) riskIndicators.push(`Many dashes (${features?.dash_count})`);
  if (features?.suspicious_tld) riskIndicators.push('Suspicious top-level domain');

  return {
    prediction,
    explanations,
    risk_indicators: [...new Set(riskIndicators)],
    safe_indicators: [...new Set(safeIndicators)],
    summary: generateSummary(prediction, riskIndicators),
    security_tips: securityTips(prediction),
  };
}

function generateSummary(prediction: Prediction, indicators: string[]): string {
  const n = indicators.length;
  switch (prediction) {
    case 'phishing':
      return `High-risk URL. Found ${n} phishing indicator${n === 1 ? '' : 's'}. Do not enter credentials on this page.`;
    case 'suspicious':
      return `Found ${n} medium-risk pattern${n === 1 ? '' : 's'}. Exercise caution - this content has some phishing indicators.`;
    default:
      return indicators.length > 0
        ? `No significant phishing patterns detected (${n} informational note${n === 1 ? '' : 's'}).`
        : 'No phishing patterns detected. Standard browsing caution still applies.';
  }
}

function securityTips(prediction: Prediction): string[] {
  if (prediction === 'phishing') {
    return [
      'Do not enter any personal information on this site',
      'Navigate to the official website by typing the address yourself',
      'Report this page to your browser or IT security team',
    ];
  }
  if (prediction === 'suspicious') {
    return [
      'Check the main domain, not just the subdomain',
      'Always verify the sender or source before acting',
      'Never click links in suspicious emails',
    ];
  }
  return ['When in doubt, navigate directly to the website', 'Keep your browser and password manager updated'];
}
