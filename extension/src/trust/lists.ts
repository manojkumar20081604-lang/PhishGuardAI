/**
 * PhishGuard AI - Trust Lists (Phase D)
 *
 * User-managed domain trust lists stored in chrome.storage.local.
 * Checked BEFORE any analysis path:
 *   trusted -> always safe (never analyzed, never nagged)
 *   blocked -> instantly flagged regardless of AI verdict
 *
 * Matching rule: a listed domain matches itself and all subdomains
 * ('example.com' covers 'login.example.com').
 */

const TRUST_KEY = 'pgai_trust_lists';

export interface TrustLists {
  trusted: string[];
  blocked: string[];
}

export type TrustListName = keyof TrustLists;
export type TrustVerdict = 'trusted' | 'blocked' | 'unlisted';

// ============================================================================
// STORAGE
// ============================================================================

export async function getLists(): Promise<TrustLists> {
  try {
    const stored = await chrome.storage.local.get(TRUST_KEY);
    const lists = stored[TRUST_KEY];
    return {
      trusted: Array.isArray(lists?.trusted) ? lists.trusted : [],
      blocked: Array.isArray(lists?.blocked) ? lists.blocked : [],
    };
  } catch {
    return { trusted: [], blocked: [] };
  }
}

async function saveLists(lists: TrustLists): Promise<void> {
  await chrome.storage.local.set({ [TRUST_KEY]: lists });
}

export async function addTo(list: TrustListName, rawDomain: string): Promise<TrustLists> {
  const domain = normalizeDomain(rawDomain);
  if (!domain) throw new Error('Invalid domain');
  const lists = await getLists();
  if (!lists[list].includes(domain)) {
    lists[list].push(domain);
    lists[list].sort();
    await saveLists(lists);
  }
  return lists;
}

export async function removeFrom(list: TrustListName, rawDomain: string): Promise<TrustLists> {
  const domain = normalizeDomain(rawDomain);
  const lists = await getLists();
  lists[list] = lists[list].filter((d) => d !== domain);
  await saveLists(lists);
  return lists;
}

/** Accepts a bare domain or a full URL; returns lowercase hostname. */
export function normalizeDomain(input: string): string {
  let value = (input || '').trim().toLowerCase();
  if (!value) return '';
  // Extract hostname from URLs like https://sub.example.com/path?x=1
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(value)) {
    try {
      value = new URL(value).hostname;
    } catch {
      return '';
    }
  }
  value = value.split('/')[0].split('?')[0].split(':').pop() ?? '';
  // Basic sanity: letters/digits/dots/hyphens only, has at least one dot
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(value)) return '';
  return value;
}

// ============================================================================
// LOOKUP
// ============================================================================

function hostMatches(host: string, entry: string): boolean {
  return host === entry || host.endsWith(`.${entry}`);
}

function hostnameOf(url: string): string {
  const normalized = normalizeDomain(url);
  return normalized; // normalizeDomain already yields bare hostname
}

/** Verdict for a URL against both lists. Blocked wins over trusted. */
export async function checkTrust(url: string): Promise<TrustVerdict> {
  const host = hostnameOf(url);
  if (!host) return 'unlisted';

  const lists = await getLists();
  if (lists.blocked.some((d) => hostMatches(host, d))) return 'blocked';
  if (lists.trusted.some((d) => hostMatches(host, d))) return 'trusted';
  return 'unlisted';
}

export async function resetLists(): Promise<void> {
  await saveLists({ trusted: [], blocked: [] });
}
