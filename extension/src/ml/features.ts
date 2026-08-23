/**
 * PhishGuard AI - URL Feature Extractor
 *
 * EXACT TypeScript port of backend/services/ml_service.py::extract_url_features.
 * Quirks are intentional (parity with the trained model matters more than elegance):
 *  - has_https checks prefix 'https', not 'https://'
 *  - suspicious TLD uses endsWith on the whole lowercased URL (paths defeat it)
 *  - feature 10 is character diversity (unique/len), not Shannon entropy
 */

export const FEATURE_NAMES = [
  'url_length',
  'has_https',
  'has_at_symbol',
  'has_ip_address',
  'dash_count',
  'digit_ratio',
  'special_char_count',
  'subdomain_count',
  'suspicious_tld',
  'char_diversity',
] as const;

const IP_PATTERN = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
const SPECIAL_CHARS = new Set("._~:/?#[]@!$&'()*+,;=".split(''));
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.club'];

/** Replicate python urlparse(url).netloc semantics closely enough for this model. */
function pyNetloc(url: string): string {
  let rest = url;
  const schemeIdx = rest.indexOf('://');
  if (schemeIdx !== -1) rest = rest.slice(schemeIdx + 3);
  const slashIdx = rest.indexOf('/');
  if (slashIdx !== -1) rest = rest.slice(0, slashIdx);
  const qIdx = rest.search(/[?#]/);
  if (qIdx !== -1) rest = rest.slice(0, qIdx);
  return rest;
}

export function extractUrlFeatures(url: string): Float32Array {
  const len = url.length;

  // 8. subdomain count: netloc.split('.') - 2, clamped at 0
  const netloc = pyNetloc(url);
  const subdomainCount = netloc ? Math.max(0, netloc.split('.').length - 2) : 0;

  let digits = 0;
  let special = 0;
  for (const c of url) {
    if (c >= '0' && c <= '9') digits++;
    if (SPECIAL_CHARS.has(c)) special++;
  }

  return new Float32Array([
    len,                                                    // url_length
    url.startsWith('https') ? 1 : 0,                        // has_https
    url.includes('@') ? 1 : 0,                              // has_at_symbol
    IP_PATTERN.test(url) ? 1 : 0,                           // has_ip_address
    (url.match(/-/g) || []).length,                         // dash_count
    digits / Math.max(len, 1),                              // digit_ratio
    special,                                                // special_char_count
    subdomainCount,                                         // subdomain_count
    SUSPICIOUS_TLDS.some((t) => url.toLowerCase().endsWith(t)) ? 1 : 0, // suspicious_tld
    new Set(url).size / Math.max(len, 1),                   // char_diversity
  ]);
}
