/**
 * PhishGuard AI - Storage Utilities (Hybrid: localStorage + SQLite)
 * Handles extension storage with Chrome/Firefox compatibility
 */

import { getDB } from '../db/database';

export interface ExtensionSettings {
  // Protection modes
  protectionMode: 'allow' | 'warn' | 'block';
  safeMode: 'allow' | 'warn' | 'block';
  suspiciousMode: 'allow' | 'warn' | 'block';
  highRiskMode: 'allow' | 'warn' | 'block';
  
  // Backend configuration
  backendEnabled: boolean;
  backendUrl: string;
  backendApiKey?: string;
  
  // Threat intelligence
  threatIntelEnabled: boolean;
  virusTotalApiKey?: string;
  phishTankApiKey?: string;
  
  // UI preferences
  showBadge: boolean;
  showNotifications: boolean;
  darkMode: boolean;
  autoAnalyze: boolean;
  
  // Privacy
  storeHistory: boolean;
  historyLimit: number;
  sendAnonymousStats: boolean;
  
  // Demo mode
  demoMode: boolean;
  
  // Advanced
  customRiskThresholds: {
    safeMax: number;
    suspiciousMax: number;
  };
}

export interface AnalysisHistoryItem {
  id: string;
  type: 'URL' | 'EMAIL' | 'TEXT' | 'PAGE';
  input: string;
  prediction: 'Phishing' | 'Suspicious' | 'Safe';
  confidence: number;
  riskScore: number;
  threatLevel: 'High' | 'Medium' | 'Low';
  reasons: string[];
  recommendations: string[];
  sources: {
    local: boolean;
    backend: boolean;
    threatIntel: boolean;
  };
  analyzedAt: string;
  url?: string;
}

export interface UserStats {
  totalScans: number;
  phishingDetected: number;
  suspiciousDetected: number;
  safeDetected: number;
  threatsBlocked: number;
  lastScanAt: string | null;
  protectionMode: string;
}

export interface ThreatCacheEntry {
  url: string;
  result: any;
  timestamp: number;
}

const DEFAULT_SETTINGS: ExtensionSettings = {
  protectionMode: 'warn',
  safeMode: 'allow',
  suspiciousMode: 'warn',
  highRiskMode: 'block',
  backendEnabled: true,
  backendUrl: 'http://localhost:5000/api',
  backendApiKey: '',
  threatIntelEnabled: true,
  virusTotalApiKey: '',
  phishTankApiKey: '',
  showBadge: true,
  showNotifications: true,
  darkMode: true,
  autoAnalyze: true,
  storeHistory: true,
  historyLimit: 100,
  sendAnonymousStats: false,
  demoMode: false,
  customRiskThresholds: {
    safeMax: 30,
    suspiciousMax: 60
  }
};

const STORAGE_KEYS = {
  SETTINGS: 'phishguard_settings',
  HISTORY: 'phishguard_history',
  STATS: 'phishguard_stats',
  THREAT_CACHE: 'phishguard_threat_cache',
  USER_PREFERENCES: 'phishguard_user_prefs'
} as const;

type StorageArea = 'local' | 'sync';

function getStorage(area: StorageArea = 'local'): chrome.storage.StorageArea {
  return area === 'sync' ? chrome.storage.sync : chrome.storage.local;
}

export async function storageGet<T>(keys: string | string[], area: StorageArea = 'local'): Promise<Record<string, T>> {
  return new Promise((resolve, reject) => {
    getStorage(area).get(keys, (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(result as Record<string, T>);
      }
    });
  });
}

export async function storageSet(data: Record<string, any>, area: StorageArea = 'local'): Promise<void> {
  return new Promise((resolve, reject) => {
    getStorage(area).set(data, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve();
      }
    });
  });
}

export async function storageRemove(keys: string | string[], area: StorageArea = 'local'): Promise<void> {
  return new Promise((resolve, reject) => {
    getStorage(area).remove(keys, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve();
      }
    });
  });
}

export async function getSettings(): Promise<ExtensionSettings> {
  const result = await storageGet<ExtensionSettings>(STORAGE_KEYS.SETTINGS);
  return { ...DEFAULT_SETTINGS, ...result[STORAGE_KEYS.SETTINGS] };
}

export async function saveSettings(settings: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
  const current = await getSettings();
  const updated = { ...current, ...settings };
  await storageSet({ [STORAGE_KEYS.SETTINGS]: updated });
  return updated;
}

export async function resetSettings(): Promise<ExtensionSettings> {
  await storageSet({ [STORAGE_KEYS.SETTINGS]: DEFAULT_SETTINGS });
  return DEFAULT_SETTINGS;
}

export async function getHistory(limit?: number): Promise<AnalysisHistoryItem[]> {
  const settings = await getSettings();
  const maxLimit = limit || settings.historyLimit || 100;
  
  // Try DB first, fall back to localStorage
  const db = getDB();
  if (db) {
    try {
      const now = new Date().toISOString();
      const history = await db.prepare(`
        SELECT id, user_id, type, input, prediction, confidence, risk_score, threat_level, 
               reasons, recommendations, sources, analyzed_at, url
        FROM scans
        ORDER BY analyzed_at DESC
        LIMIT ?
      `).all(maxLimit) as any[];
      
      return history.map(h => ({
        id: h.id,
        type: h.type,
        input: h.input,
        prediction: h.prediction,
        confidence: h.confidence,
        riskScore: h.risk_score,
        threatLevel: h.threat_level,
        reasons: JSON.parse(h.reasons),
        recommendations: JSON.parse(h.recommendations),
        sources: JSON.parse(h.sources),
        analyzedAt: h.analyzed_at,
        url: h.url
      }));
    } catch (e) {
      console.warn('DB history query failed, falling back to localStorage:', e);
    }
  }
  
  // Fallback to localStorage
  const result = await storageGet<AnalysisHistoryItem[]>(STORAGE_KEYS.HISTORY);
  const history = result[STORAGE_KEYS.HISTORY] || [];
  return history.slice(0, maxLimit);
}

export async function addToHistory(item: Omit<AnalysisHistoryItem, 'id'>): Promise<AnalysisHistoryItem> {
  const settings = await getSettings();
  
  // Try DB first if enabled
  const db = getDB();
  if (db && settings.storeHistory) {
    try {
      const newItem: AnalysisHistoryItem = {
        ...item,
        id: `pg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      };
      
      await db.prepare(`
        INSERT INTO scans (id, user_id, type, input, prediction, confidence, risk_score, 
                          threat_level, reasons, recommendations, sources, analyzed_at, url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        newItem.id,
        null, // user_id (anonymous for now)
        newItem.type,
        newItem.input,
        newItem.prediction,
        newItem.confidence,
        newItem.riskScore,
        newItem.threatLevel,
        JSON.stringify(newItem.reasons),
        JSON.stringify(newItem.recommendations),
        JSON.stringify({ local: true, backend: false, threatIntel: false }),
        new Date().toISOString(),
        newItem.url
      );
      
      // Update stats in DB
      const stats = await getStats();
      stats.totalScans++;
      stats.lastScanAt = new Date().toISOString();
      
      switch (item.prediction) {
        case 'Phishing':
          stats.phishingDetected++;
          if (item.threatLevel === 'High') stats.threatsBlocked++;
          break;
        case 'Suspicious':
          stats.suspiciousDetected++;
          break;
        case 'Safe':
          stats.safeDetected++;
          break;
      }
      
      await saveStats(stats);
      
      return newItem;
    } catch (e) {
      console.warn('DB history insert failed, falling back to localStorage:', e);
    }
  }
  
  // Fallback to localStorage
  const result = await storageGet<AnalysisHistoryItem[]>(STORAGE_KEYS.HISTORY);
  const history = result[STORAGE_KEYS.HISTORY] || [];
  
  const newItem: AnalysisHistoryItem = {
    ...item,
    id: `pg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  };
  
  const updated = [newItem, ...history].slice(0, settings.historyLimit);
  await storageSet({ [STORAGE_KEYS.HISTORY]: updated });
  
  // Update stats (localStorage fallback)
  await updateStats(item);
  
  return newItem;
}

export async function clearHistory(): Promise<void> {
  const db = getDB();
  if (db) {
    try {
      await db.prepare('DELETE FROM scans').run();
      console.log('DB history cleared');
    } catch (e) {
      console.warn('DB history delete failed:', e);
    }
  }
  
  // Also clear localStorage
  await storageRemove(STORAGE_KEYS.HISTORY);
}

export async function getStats(): Promise<UserStats> {
  const db = getDB();
  if (db) {
    try {
      const stats = await db.prepare(`
        SELECT 
          COUNT(*) as totalScans,
          SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishingDetected,
          SUM(CASE WHEN prediction = 'Suspicious' THEN 1 ELSE 0 END) as suspiciousDetected,
          SUM(CASE WHEN prediction = 'Safe' THEN 1 ELSE 0 END) as safeDetected,
          SUM(CASE WHEN threat_level = 'High' AND prediction = 'Phishing' THEN 1 ELSE 0 END) as threatsBlocked,
          MAX(analyzed_at) as lastScanAt
        FROM scans
      `).get() as any;
      
      return {
        totalScans: stats.totalScans || 0,
        phishingDetected: stats.phishingDetected || 0,
        suspiciousDetected: stats.suspiciousDetected || 0,
        safeDetected: stats.safeDetected || 0,
        threatsBlocked: stats.threatsBlocked || 0,
        lastScanAt: stats.lastScanAt || null,
        protectionMode: 'warn'
      };
    } catch (e) {
      console.warn('DB stats query failed:', e);
    }
  }
  
  // Fallback to localStorage
  const result = await storageGet<UserStats>(STORAGE_KEYS.STATS);
  return result[STORAGE_KEYS.STATS] || {
    totalScans: 0,
    phishingDetected: 0,
    suspiciousDetected: 0,
    safeDetected: 0,
    threatsBlocked: 0,
    lastScanAt: null,
    protectionMode: 'warn'
  };
}

async function updateStats(item: Omit<AnalysisHistoryItem, 'id'>): Promise<void> {
  const stats = await getStats();
  
  stats.totalScans++;
  stats.lastScanAt = new Date().toISOString();
  
  switch (item.prediction) {
    case 'Phishing':
      stats.phishingDetected++;
      if (item.threatLevel === 'High') stats.threatsBlocked++;
      break;
    case 'Suspicious':
      stats.suspiciousDetected++;
      break;
    case 'Safe':
      stats.safeDetected++;
      break;
  }
  
  await saveStats(stats);
}

export async function saveStats(stats: UserStats): Promise<void> {
  const db = getDB();
  if (db) {
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO stats (id, total_scans, phishing_detected, suspicious_detected, 
                                      safe_detected, threats_blocked, last_scan_at, protection_mode)
        VALUES ('default', ?, ?, ?, ?, ?, ?, ?)
      `).run(
        stats.totalScans,
        stats.phishingDetected,
        stats.suspiciousDetected,
        stats.safeDetected,
        stats.threatsBlocked,
        stats.lastScanAt || '',
        stats.protectionMode
      );
    } catch (e) {
      console.warn('DB stats update failed:', e);
    }
  }
  
  // Also save to localStorage for redundancy
  await storageSet({ [STORAGE_KEYS.STATS]: stats });
}

export async function getThreatCache(): Promise<Record<string, ThreatCacheEntry>> {
  const db = getDB();
  if (db) {
    try {
      const cache = await db.prepare(`
        SELECT url, result, timestamp FROM threat_cache
      `).all() as any[];
      
      return Object.fromEntries(
        cache.map(c => [c.url, {
          url: c.url,
          result: JSON.parse(c.result),
          timestamp: c.timestamp
        }])
      );
    } catch (e) {
      console.warn('DB threat cache query failed:', e);
    }
  }
  
  const result = await storageGet<Record<string, ThreatCacheEntry>>(STORAGE_KEYS.THREAT_CACHE);
  return result[STORAGE_KEYS.THREAT_CACHE] || {};
}

export async function setThreatCache(url: string, result: any): Promise<void> {
  const db = getDB();
  if (db) {
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO threat_cache (url, result, timestamp, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(url, JSON.stringify(result), Date.now(), Date.now() + 24 * 60 * 60 * 1000); // 24h expiry
    } catch (e) {
      console.warn('DB threat cache insert failed:', e);
    }
  }
  
  // Also update localStorage for redundancy
  const cache = await getThreatCache();
  cache[url] = { url, result, timestamp: Date.now() };
  await storageSet({ [STORAGE_KEYS.THREAT_CACHE]: cache });
}

export async function cleanThreatCache(maxAge = 24 * 60 * 60 * 1000): Promise<void> {
  const db = getDB();
  if (db) {
    try {
      await db.prepare(`
        DELETE FROM threat_cache WHERE timestamp < ?
      `).run(Date.now() - maxAge);
    } catch (e) {
      console.warn('DB threat cache cleanup failed:', e);
    }
  }
  
  const cache = await getThreatCache();
  let changed = false;
  
  for (const url of Object.keys(cache)) {
    if (Date.now() - cache[url].timestamp > maxAge) {
      delete cache[url];
      changed = true;
    }
  }
  
  if (changed) {
    await storageSet({ [STORAGE_KEYS.THREAT_CACHE]: cache });
  }
}

export async function exportUserData(): Promise<{
  settings: ExtensionSettings;
  history: AnalysisHistoryItem[];
  stats: UserStats;
}> {
  const [settings, history, stats] = await Promise.all([
    getSettings(),
    getHistory(),
    getStats()
  ]);
  
  return { settings, history, stats };
}

export async function importUserData(data: {
  settings?: ExtensionSettings;
  history?: AnalysisHistoryItem[];
  stats?: UserStats;
}): Promise<void> {
  const promises: Promise<void>[] = [];
  
  if (data.settings) {
    promises.push(storageSet({ [STORAGE_KEYS.SETTINGS]: data.settings }));
  }
  if (data.history) {
    promises.push(storageSet({ [STORAGE_KEYS.HISTORY]: data.history }));
  }
  if (data.stats) {
    promises.push(storageSet({ [STORAGE_KEYS.STATS]: data.stats }));
  }
  
  await Promise.all(promises);
}

export function onSettingsChange(callback: (changes: { [key: string]: chrome.storage.StorageChange }) => void): void {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes[STORAGE_KEYS.SETTINGS]) {
      callback(changes);
    }
  });
}

export async function getSetting<K extends keyof ExtensionSettings>(key: K): Promise<ExtensionSettings[K]> {
  const settings = await getSettings();
  return settings[key];
}

export async function setSetting<K extends keyof ExtensionSettings>(key: K, value: ExtensionSettings[K]): Promise<void> {
  await saveSettings({ [key]: value });
}
