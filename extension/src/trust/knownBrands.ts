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
 * Trade-off: phishing hosted ON these exact domains (open redirects)
 * will not be flagged locally - acceptable, documented trade-off.
 */

export const KNOWN_GOOD_DOMAINS: readonly string[] = [
  // Search / Google ecosystem
  'google.com', 'youtube.com', 'gmail.com', 'blogger.com',
  // AI services
  'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
  'gemini.google.com', 'perplexity.ai', 'huggingface.co',
  // Dev platforms
  'github.com', 'gitlab.com', 'stackoverflow.com', 'npmjs.com',
  'vercel.app', 'netlify.app', 'codepen.io',
  // Commerce / cloud
  'amazon.com', 'aws.amazon.com', 'azure.microsoft.com', 'microsoft.com',
  'live.com', 'office.com', 'microsoftonline.com', 'apple.com', 'icloud.com',
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
