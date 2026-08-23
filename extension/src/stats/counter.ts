/**
 * PhishGuard AI - Verdict Statistics Ledger (Phase G)
 *
 * Durable counters in chrome.storage.local - independent from the 50-entry
 * scan cache so history charts survive cache trimming.
 *
 * Shape:
 *   { totalScans, phishingBlocked, suspiciousSeen, safeVisits,
 *     byDay: { 'YYYY-MM-DD': { scans, threats } }, updatedAt }
 */

const STATS_KEY = 'pgai_stats';
const DAY_RETENTION = 35; // keep a little more than the 14-day window

export interface DayStat {
  scans: number;
  threats: number;
}

export interface PgStats {
  totalScans: number;
  phishingBlocked: number;
  suspiciousSeen: number;
  safeVisits: number;
  byDay: Record<string, DayStat>;
  updatedAt: string;
}

function emptyStats(): PgStats {
  return {
    totalScans: 0,
    phishingBlocked: 0,
    suspiciousSeen: 0,
    safeVisits: 0,
    byDay: {},
    updatedAt: new Date().toISOString(),
  };
}

export async function getStats(): Promise<PgStats> {
  try {
    const stored = await chrome.storage.local.get(STATS_KEY);
    return stored[STATS_KEY] ?? emptyStats();
  } catch {
    return emptyStats();
  }
}

/** Record one analysis outcome. Skips nothing here - callers decide relevance. */
export async function recordVerdict(result: {
  prediction?: string;
  risk_score?: number;
  source?: string;
}): Promise<void> {
  // Trust-list "trusted" skips are not real analyses - never inflate numbers
  if (result.source === 'trust-list' && String(result.prediction) === 'safe') return;

  const pred = String(result.prediction ?? 'safe').toLowerCase();
  const score = Number(result.risk_score ?? 0);
  const isThreat =
    pred === 'phishing' || score >= 65 ||
    (result.source === 'trust-list' && pred !== 'safe');

  const stats = await getStats();
  const today = dayKey(new Date());

  stats.totalScans += 1;
  if (isThreat) stats.phishingBlocked += 1;
  else if (pred === 'suspicious' || score >= 35) stats.suspiciousSeen += 1;
  else stats.safeVisits += 1;

  const day = stats.byDay[today] ?? { scans: 0, threats: 0 };
  day.scans += 1;
  if (isThreat) day.threats += 1;
  stats.byDay[today] = day;

  pruneOldDays(stats);
  stats.updatedAt = new Date().toISOString();

  try {
    await chrome.storage.local.set({ [STATS_KEY]: stats });
  } catch (error) {
    console.warn('[Stats] write failed:', error);
  }
}

export async function resetStats(): Promise<PgStats> {
  const fresh = emptyStats();
  try {
    await chrome.storage.local.set({ [STATS_KEY]: fresh });
  } catch (error) {
    console.warn('[Stats] reset failed:', error);
  }
  return fresh;
}

/** Sum of threats over the trailing N days (inclusive of today). */
export function threatsInLastDays(stats: PgStats, days: number): number {
  let sum = 0;
  for (let i = 0; i < days; i++) {
    const key = dayKey(new Date(Date.now() - i * 86400_000));
    sum += stats.byDay[key]?.threats ?? 0;
  }
  return sum;
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10); // UTC date key - stable across timezones
}

function pruneOldDays(stats: PgStats): void {
  const cutoff = Date.now() - DAY_RETENTION * 86400_000;
  for (const key of Object.keys(stats.byDay)) {
    if (new Date(`${key}T00:00:00Z`).getTime() < cutoff) {
      delete stats.byDay[key];
    }
  }
}
