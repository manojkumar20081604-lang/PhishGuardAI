/**
 * PhishGuard AI - Known-Brand Domain Prior
 *
 * A small curated list of major consumer/service domains. If a URL's
 * registered domain EXACTLY matches one of these (incl. subdomains), the
 * local engine treats it as trusted infrastructure and downgrades any
 * ML verdict to safe.
 *
 * Rationale: with 10 string-only features, `chatgpt.com/c/<uuid>` and
 * `scam.example/c/<uuid>` are near-identical; the separating signal is
 * domain reputation, which this list encodes for the sites people
 * actually use. Look-alikes (`chatgpt-secure.xyz`) do NOT match.
 *
 * Trade-off: open redirects ON these exact domains will not be flagged
 * locally - acceptable, documented trade-off.
 *
 * NOTE (v3.2.1): free-hosting platforms (netlify.app, vercel.app) were
 * REMOVED from this list. Their subdomains are user-controlled content and
 * a top phishing-abuse vector - `scam-page.netlify.app` must never inherit
 * Netlify's reputation.
 */

export const KNOWN_GOOD_DOMAINS: readonly string[] = [
  // Search / Google ecosystem
  'google.com', 'youtube.com', 'gmail.com', 'blogger.com',
  // AI services
  'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
  'gemini.google.com', 'perplexity.ai', 'huggingface.co',
  // Dev platforms (first-party domains only - NOT user-content hosting)
  'github.com', 'gitlab.com', 'stackoverflow.com', 'npmjs.com',
  'codepen.io',
  // Commerce / cloud
  'amazon.com', 'aws.amazon.com', 'azure.microsoft.com', 'microsoft.com',
  'live.com', 'office.com', 'microsoftonline.com', 'apple.com', 'icloud.com',
  // Real country-TLD variants of major brands (verified registrations only -
  // never assume <brand>.<any-tld> is safe, scammers buy look-alike TLDs)
  'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.ae',
  'google.co.in', 'google.co.uk', 'google.de',
  'flipkart.com', 'myntra.com', 'zomato.com', 'swiggy.com',
  // Social / content
  'facebook.com', 'instagram.com', 'whatsapp.com', 'x.com', 'twitter.com',
  'reddit.com', 'linkedin.com', 'tiktok.com', 'pinterest.com',
  'discord.com', 'twitch.tv', 'medium.com', 'quora.com',
  // Media / productivity
  'netflix.com', 'spotify.com', 'primevideo.com', 'hotstar.com',
  'notion.so', 'dropbox.com', 'zoom.us', 'slack.com',
  'wikipedia.org', 'archive.org', 'mozilla.org',
  // Finance / commerce (exact infra only)
  'paypal.com', 'ebay.com', 'stripe.com', 'razorpay.com',
  'coinbase.com', 'binance.com',
];

function registeredHost(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    // bare-domain or malformed - fall back to naive parse
    let v = url.trim().toLowerCase();
    if (v.includes('://')) v = v.split('://')[1] ?? '';
    return v.split('/')[0].split('?')[0];
  }
}

/** True when host equals a known-good domain or is a subdomain of one. */
export function isKnownGoodDomain(url: string): boolean {
  const host = registeredHost(url);
  if (!host || !host.includes('.')) return false;
  return KNOWN_GOOD_DOMAINS.some(
    (d) => host === d || host.endsWith(`.${d}`)
  );
}
