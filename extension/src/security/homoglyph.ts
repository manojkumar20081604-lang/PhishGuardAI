/**
 * PhishGuard AI - Homoglyph / Punycode Detector (v3.2)
 *
 * Catches look-alike domain scams purely with offline string math:
 *   - Mixed-script hosts ("аpple.com" with a Cyrillic 'а')
 *   - Punycode (xn--) labels whose decoded form mixes scripts
 *   - Invisible characters (zero-width, bidi controls)
 *   - Exact visual clones of known brands after confusable folding
 *
 * False-positive safety rules:
 *   - Pure non-Latin IDNs (e.g. Japanese punycode) are NOT flagged
 *   - Only brand imitation and invisible characters escalate the verdict;
 *     everything else just adds explanatory reasons
 */

import { KNOWN_GOOD_DOMAINS } from '../trust/knownBrands';

export interface HomoglyphReport {
  /** Human-readable risk factors found (may be empty). */
  reasons: string[];
  /** Known brand being imitated via look-alike characters, if any. */
  brandImitation: string | null;
  /** True when the URL must be treated as at least suspicious. */
  escalate: boolean;
}

// ============================================================================
// CONFUSABLE FOLDING (curated set covering the common scam alphabet)
// ============================================================================

/** Look-alike codepoints folded to their ASCII twin. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'і': 'i', 'ѕ': 's', 'ј': 'j', 'ә': 'a', 'ғ': 'r', 'қ': 'k', 'ң': 'n',
  // Cyrillic round 2 - covers the аррӏе/apple-class kits
  'ӏ': 'l', 'в': 'b', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't',
  'ԁ': 'd', 'һ': 'h', 'ѡ': 'w', 'ѣ': 'a',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'τ': 't',
  'υ': 'u', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'χ': 'x',
  'ϳ': 'j', 'ϲ': 'c', 'λ': 'l', 'η': 'n', 'μ': 'm',
  // Armenian (common in homograph kits)
  'հ': 'h', 'օ': 'o', 'ց': 'g', 'ո': 'n', 'ւ': 'u',
  // Latin extensions
  'ı': 'i', 'ſ': 's',
};

/** Characters that should never appear in a real hostname. */
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/;

/** Script classes that mix badly with Latin within one label. */
const NON_LATIN_LETTERS: Array<[string, RegExp]> = [
  ['Cyrillic', /[\u0400-\u04FF]/],
  ['Greek', /[\u0370-\u03FF]/],
  ['Armenian', /[\u0530-\u058F]/],
];

function foldToAscii(text: string): string {
  return text
    .split('')
    .map((ch) => CONFUSABLES[ch] ?? ch)
    .join('')
    .toLowerCase();
}

// ============================================================================
// PUNYCODE DECODE (RFC 3492 decoder only - ~40 lines, zero dependency)
// ============================================================================

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adaptBias(delta: number, numPoints: number, firstTime: boolean): number {
  delta = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) / 2) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function decodeDigit(ch: string): number {
  const cp = ch.codePointAt(0)!;
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41; // A-Z -> 0..25
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61; // a-z -> 0..25
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26; // 0-9 -> 26..35
  return -1;
}

export function punycodeDecode(input: string): string | null {
  const output: number[] = [];
  const basicEnd = input.lastIndexOf('-');
  if (basicEnd > 0) {
    for (let i = 0; i < basicEnd; i++) {
      const ch = input.charCodeAt(i);
      if (ch >= 0x80) return null;
      output.push(ch);
    }
  }
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  let index = basicEnd > 0 ? basicEnd + 1 : 0;
  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) return null;
      const digit = decodeDigit(input[index++]);
      if (digit < 0) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adaptBias(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i++;
  }
  try {
    return String.fromCodePoint(...output);
  } catch {
    return null;
  }
}

// ============================================================================
// HELPERS
// ============================================================================

interface HostInfo {
  /** Host as the browser displays it (punycode labels decoded). */
  displayHost: string;
  /** True if any label required punycode decoding. */
  hadPunycode: boolean;
}

/** new URL().hostname gives punycode - decode each label back to Unicode. */
function readableHost(url: string): HostInfo | null {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!host || !host.includes('.')) return null;
  let hadPunycode = false;
  const displayLabels = host.split('.').filter(Boolean).map((label) => {
    if (!label.startsWith('xn--')) return label;
    const decoded = punycodeDecode(label.slice(4));
    if (decoded === null) return label;
    hadPunycode = true;
    return decoded;
  });
  return { displayHost: displayLabels.join('.'), hadPunycode };
}

function scriptsInText(text: string): Set<string> {
  const scripts = new Set<string>();
  if (/[a-z]/i.test(text)) scripts.add('Latin');
  for (const [name, re] of NON_LATIN_LETTERS) {
    if (re.test(text)) scripts.add(name);
  }
  return scripts;
}

// ============================================================================
// MAIN ENTRY
// ============================================================================

export function inspectHomoglyph(url: string): HomoglyphReport {
  const report: HomoglyphReport = { reasons: [], brandImitation: null, escalate: false };
  const info = readableHost(url);
  if (!info) return report;

  const { displayHost } = info;
  const labels = displayHost.split('.');
  const registrable = labels.slice(-2).join('.');

  // 1. Invisible characters - never legitimate, always escalate.
  //    Checked against the RAW string: URL parsers strip these from the
  //    hostname before we ever see them.
  if (INVISIBLE.test(url) || INVISIBLE.test(displayHost)) {
    report.reasons.push('URL contains invisible/manipulation characters');
    report.escalate = true;
  }

  // 2. Mixed scripts inside a single label (e.g. Cyrillic а inside Latin word)
  const mixedScripts = new Set<string>();
  for (const label of labels) {
    const scripts = scriptsInText(label);
    if (scripts.size > 1) {
      for (const s of scripts) if (s !== 'Latin') mixedScripts.add(s);
    }
  }
  if (mixedScripts.size > 0) {
    report.reasons.push(
      `Domain mixes Latin with ${[...mixedScripts].join('/')} characters (classic look-alike trick)`
    );
  }

  // 3. Punycode context - note it when relevant, never punish plain IDNs
  if (info.hadPunycode && mixedScripts.size > 0) {
    report.reasons.push(`Punycode label displays as "${displayHost}"`);
  }

  // 4. Brand imitation: fold look-alike chars, then require an EXACT match
  //    against a known-brand domain while the raw domain differs.
  const folded = foldToAscii(registrable);
  const hasNonAscii = Array.from(registrable).some((ch) => ch.charCodeAt(0) > 127);
  if ((folded !== registrable || info.hadPunycode) && hasNonAscii) {
    const brand = KNOWN_GOOD_DOMAINS.find((b) => b === folded);
    if (brand && registrable.toLowerCase() !== brand) {
      report.brandImitation = brand;
      report.reasons.push(`Domain imitates "${brand}" using look-alike characters`);
    }
  }

  // Escalation policy: invisible chars and confirmed brand imitation are hard
  // signals; plain script mixing only adds reasons (FP-safe).
  if (report.brandImitation) report.escalate = true;
  return report;
}
