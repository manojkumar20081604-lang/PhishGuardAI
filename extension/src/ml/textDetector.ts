/**
 * PhishGuard AI - Message Text Detector (Phase H)
 *
 * Offline TypeScript port of the legacy email_detector.py + sms_detector.py.
 * Both rule engines ALWAYS run; the higher score wins, so a misdetected
 * type can never hide an attack. Extracted URLs are additionally verified
 * by the ONNX URL engine and escalate the verdict when flagged.
 */

import { predictUrl } from './engine';

export interface MessageScanResult {
  prediction: 'safe' | 'suspicious' | 'phishing';
  confidence: number;
  risk_score: number;
  detected_type: 'email' | 'sms';
  reasons: string[];
  security_tips: string[];
  summary: string;
  extracted_urls: string[];
}

// ---------------------------------------------------------------------------
// Legacy email_detector.py word banks
// ---------------------------------------------------------------------------

const EMAIL_URGENCY = [
  'urgent', 'immediately', 'right away', 'act now', 'limited time',
  'expire', 'suspended', 'verify', 'confirm', 'update', 'security',
  'alert', 'warning', 'danger', 'attention', 'final notice',
  'deadline', 'unauthorized', 'unusual activity', 'suspicious',
  'click here', 'call now', 'act immediately', 'within 24 hours',
  'your account', 'will be closed', 'must verify', 'confirm identity',
];

const EMAIL_SUSPICIOUS = [
  'wire transfer', 'gift card', 'bitcoin', 'cryptocurrency',
  'lottery winner', 'inheritance', 'prince', 'million dollars',
  'bank account', 'social security', 'password', 'credit card',
  'ssn', 'tax refund', 'refund', 'prize', 'winner',
];

const EMAIL_THREATS = [
  'legal action', 'lawsuit', 'arrest', 'court', 'federal',
  'police', 'authorities', 'prosecute', 'guilty', 'deported',
];

// ---------------------------------------------------------------------------
// Legacy sms_detector.py pattern banks
// ---------------------------------------------------------------------------

const SMS_SMISHING_PATTERNS = [
  /bank\s+account/, /activate\s+now/, /debit\s+card/, /credit\s+card/,
  /pin\s+(?:is|changed)/, /otp\s*[:=]/, /verify\s+account/,
  /suspend(?:ed)?\s+account/, /urgent\s+action/, /kyc\s+update/i,
  /compliance/, /reserve\s+fund/, /block(?:ed)?\s+(?:card|account)/,
  /unusual\s+(?:activity|login)/, /confirm\s+identity/,
  /immediate\s+attention/, /transaction\s+alert/, /refund\s+process/,
  /balance\s+update/, /limit\s+(?:exceeded|reached)/,
];

const SMS_URGENCY = [
  'immediately', 'urgent', 'right now', 'within', 'hours', 'today',
  'expires', 'limited', 'last chance', 'act now', 'final',
];

const SMS_BANK = [
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'bank', 'banking',
  'account', 'wallet', 'upi', 'neft', 'rtgs', 'debit', 'credit',
];

const SMS_REWARD = [
  'won', 'winner', 'prize', 'lottery', 'gift', 'reward', 'cashback',
  'scratch', 'reward points', 'voucher', 'coupon', 'claim',
];

// ---------------------------------------------------------------------------
// Detection & helpers
// ---------------------------------------------------------------------------

export function detectMessageType(text: string): 'email' | 'sms' {
  const t = text.trim();
  if (/^from:|^subject:/im.test(t)) return 'email';
  if (/[\w.-]+@[\w.-]+\.\w+/.test(t) && t.length > 200) return 'email';
  return 'sms';
}

function extractUrls(text: string): string[] {
  const raw = text.match(/https?:\/\/[^\s<>"']+/gi) ?? [];
  const www = text.match(/(?<![\w.])www\.[^\s<>"']+/gi) ?? [];
  const all = [...raw, ...www.map((u) => `http://${u}`)];
  return [...new Set(all)].slice(0, 5);
}

const countHits = (text: string, words: string[]): number =>
  words.reduce((n, w) => n + (text.includes(w) ? 1 : 0), 0);

// ---------------------------------------------------------------------------
// Rule engines (scores mirror the Python originals)
// ---------------------------------------------------------------------------

interface EngineResult {
  score: number;
  reasons: string[];
}

function runEmailRules(text: string): EngineResult {
  const lower = text.toLowerCase();
  const score = { value: 0, reasons: [] as string[] };
  const add = (pts: number, reason: string) => {
    score.value += pts;
    score.reasons.push(reason);
  };

  const urgency = countHits(lower, EMAIL_URGENCY);
  if (urgency >= 3) add(30, `High urgency language (${urgency} urgency indicators)`);
  else if (urgency >= 1) add(15, 'Contains urgency-triggering words');

  const suspicious = countHits(lower, EMAIL_SUSPICIOUS);
  if (suspicious >= 2) add(25, 'Contains suspicious financial phrases');
  else if (suspicious >= 1) add(10, 'Contains potentially suspicious content');

  if (countHits(lower, EMAIL_THREATS) >= 1) add(20, 'Contains threatening language');

  const urls = extractUrls(text);
  if (urls.length >= 2) add(20, `Multiple URLs embedded (${urls.length} links)`);
  else if (urls.length === 1) add(10, 'Contains embedded URL');

  const capsRatio = [...text].filter((c) => c >= 'A' && c <= 'Z').length / Math.max(text.length, 1);
  if (capsRatio > 0.3) add(10, 'Excessive use of capital letters');

  const greetings = /^(dear|hello|hi|greetings|good)/i.test(text.trim());
  if (!greetings && text.length > 120) add(5, 'Missing or unusual greeting');

  const signed = /\b(regards|sincerely|best|thanks)\b/i.test(text);
  if (!signed && text.length > 200) add(5, 'Missing professional signature');

  const exclamations = (text.match(/!/g) ?? []).length;
  if (exclamations > 3) add(10, 'Excessive exclamation marks');

  return { score: Math.min(score.value, 100), reasons: score.reasons };
}

function runSmsRules(text: string): EngineResult {
  const lower = text.toLowerCase();
  const score = { value: 0, reasons: [] as string[] };
  const add = (pts: number, reason: string) => {
    score.value += pts;
    score.reasons.push(reason);
  };

  const smishing = SMS_SMISHING_PATTERNS.filter((p) => p.test(lower)).length;
  if (smishing >= 3) add(40, `Strong SMiShing indicators detected (${smishing})`);
  else if (smishing >= 1) add(20, 'Contains SMiShing patterns');

  const bank = countHits(lower, SMS_BANK);
  if (bank >= 2) add(25, 'Multiple bank/financial mentions');
  else if (bank >= 1) add(10, 'Contains financial terminology');

  if (countHits(lower, SMS_URGENCY) >= 2) add(20, 'Creates urgency to act quickly');

  const otpRequest = /\b(otp|password|pin)\b/i.test(lower);
  if (otpRequest) add(30, 'Requests OTP/password - critical scam indicator');

  const links = extractUrls(text).length + (text.match(/bit\.ly[^\s]+/gi) ?? []).length;
  if (links >= 1) add(20, `Contains ${links} suspicious link(s)`);

  if (countHits(lower, SMS_REWARD) >= 1) add(15, 'Contains prize/reward language');

  const shortCode = /\b\d{4,6}\b/.test(text);
  if (shortCode) add(10, 'Contains short numeric code');

  return { score: Math.min(score.value, 100), reasons: score.reasons };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function scanMessage(text: string): Promise<MessageScanResult> {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error('Paste an email or SMS text to analyze.');
  }

  const detectedType = detectMessageType(trimmed);

  // Both engines always run - highest score wins
  const email = runEmailRules(trimmed);
  const sms = runSmsRules(trimmed);
  const winner = sms.score >= email.score ? 'sms' : 'email';

  // URL escalation: verify every extracted link with the ONNX engine
  const extractedUrls = extractUrls(trimmed);
  const reasons = new Set<string>([
    ...(winner === 'sms' ? sms.reasons : email.reasons),
    ...(sms.score > 0 ? sms.reasons : []),
    ...(email.score > 0 ? email.reasons : []),
  ]);

  let score = Math.max(email.score, sms.score);

  for (const url of extractedUrls) {
    try {
      const { prediction } = await predictUrl(url);
      if (prediction === 'phishing') {
        score = Math.min(score + 40, 100);
        reasons.add(`Linked page confirmed dangerous by URL AI: ${truncate(url, 48)}`);
        break;
      }
      if (prediction === 'suspicious') {
        score = Math.min(score + 15, 100);
        reasons.add(`Linked page looks suspicious: ${truncate(url, 48)}`);
      }
    } catch {
      // Link check failure must never fail the whole message scan
    }
  }

  score = Math.min(score, 100);
  const prediction: MessageScanResult['prediction'] =
    score > 60 ? 'phishing' : score > 30 ? 'suspicious' : 'safe';
  const confidence =
    prediction === 'safe' ? Math.round((1 - score / 100) * 1000) / 1000 : Math.round((score / 100) * 1000) / 1000;

  return {
    prediction,
    confidence,
    risk_score: score,
    detected_type: detectedType,
    reasons: [...reasons],
    security_tips: tipsFor(prediction),
    summary: summarize(detectedType, prediction, reasons.size),
    extracted_urls: extractedUrls,
  };
}

function summarize(type: 'email' | 'sms', prediction: string, indicatorCount: number): string {
  const kind = type === 'email' ? 'email/message' : 'SMS/text';
  switch (prediction) {
    case 'phishing':
      return `This ${kind} shows strong scam indicators (${indicatorCount}). Do not reply, click links, or share codes.`;
    case 'suspicious':
      return `Found ${indicatorCount} suspicious pattern${indicatorCount === 1 ? '' : 's'} in this ${kind}. Verify through official channels before acting.`;
    default:
      return `No significant scam patterns found in this ${kind}. Standard caution still applies.`;
  }
}

function tipsFor(prediction: MessageScanResult['prediction']): string[] {
  if (prediction === 'phishing') {
    return [
      'Never share OTPs or passwords - no legitimate service asks for them',
      'Do not click links; open the official app or website yourself',
      'Report and delete the message',
    ];
  }
  if (prediction === 'suspicious') {
    return [
      'Contact the organization using their official number',
      'Hover over links to inspect the real destination',
      'Be extra careful if the message creates urgency',
    ];
  }
  return ['Stay alert even with normal-looking messages', 'Verify unexpected requests through known contacts'];
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
