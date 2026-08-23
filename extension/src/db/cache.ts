/**
 * Local Cache Layer - IndexedDB for recent scans and UI state
 *
 * Usage pattern (per plan):
 *   const result = await scanApi.analyzeUrl(url);
 *   await cache.set(url, result);   // Cache AFTER successful API call
 */

import { ScanCacheEntry } from '../services/baseApi';

export type ScanCache = ScanCacheEntry;

const DB_NAME = 'PhishGuardDB';
const DB_VERSION = 1;
const STORE_NAME = 'scanCache';
const MAX_CACHE_SIZE = 50; // Keep last 50 scans by default

let db: IDBDatabase | null = null;

// ============================================================================
// INDEXEDDB SETUP
// ============================================================================

export async function initDb(): Promise<IDBDatabase> {
  if (db) return db;

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const database = (event.target as IDBOpenDBRequest).result;

      if (!database.objectStoreNames.contains(STORE_NAME)) {
        const store = database.createObjectStore(STORE_NAME, { keyPath: 'session_id' });
        store.createIndex('url', 'url', { unique: false });
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      db = request.result;
      db.onclose = () => { db = null; };
      console.log('[CacheDB] Database ready');
      resolve(db);
    };
  });
}

async function getStore(mode: IDBTransactionMode): Promise<IDBObjectStore> {
  const database = await initDb();
  return database.transaction([STORE_NAME], mode).objectStore(STORE_NAME);
}

// ============================================================================
// CACHE OPERATIONS
// ============================================================================

/** Store a scan result AFTER a successful API call. */
export async function set(url: string, result: Partial<ScanCache> & { url?: string }): Promise<void> {
  const store = await getStore('readwrite');

  const entry: ScanCache = {
    session_id: result.session_id || generateSessionId(url),
    url: url,
    risk_score: result.risk_score ?? 0,
    prediction: result.prediction ?? 'safe',
    summary: result.summary,
    timestamp: Date.now(),
  };

  return new Promise((resolve, reject) => {
    const request = store.put(entry);
    request.onsuccess = () => {
      cleanupOldEntries()
        .then(resolve)
        .catch((e) => {
          console.warn('[CacheDB] Cleanup failed:', e);
          resolve(); // Cleanup failure should not fail the write
        });
    };
    request.onerror = () => reject(request.error);
  });
}

/** Return cached scan for a URL, if any. */
export async function get(url: string): Promise<ScanCache | null> {
  const store = await getStore('readonly');

  return new Promise((resolve, reject) => {
    const request = store.index('url').get(url);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

/** Get recent scans (most recent first), up to `limit`. */
export async function list(limit: number = MAX_CACHE_SIZE): Promise<ScanCache[]> {
  const store = await getStore('readonly');

  return new Promise((resolve, reject) => {
    const request = store.index('timestamp').openCursor(null, 'prev');
    const results: ScanCache[] = [];

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
      if (!cursor || results.length >= limit) {
        resolve(results);
        return;
      }
      results.push(cursor.value);
      cursor.continue();
    };

    request.onerror = () => reject(request.error);
  });
}

/** Clear all cached data. */
export async function clear(): Promise<void> {
  const store = await getStore('readwrite');

  return new Promise((resolve, reject) => {
    const request = store.clear();
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function isDbReady(): Promise<boolean> {
  try {
    await initDb();
    return true;
  } catch {
    return false;
  }
}

// ============================================================================
// INTERNALS
// ============================================================================

/** Trim cache to MAX_CACHE_SIZE, deleting oldest entries first. */
async function cleanupOldEntries(): Promise<void> {
  const store = await getStore('readwrite');

  return new Promise((resolve, reject) => {
    const request = store.index('timestamp').openCursor(null, 'next'); // oldest first
    let seen = 0;

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
      if (!cursor) {
        resolve();
        return;
      }
      seen++;
      if (seen > MAX_CACHE_SIZE) {
        cursor.delete();
      }
      cursor.continue();
    };

    request.onerror = () => reject(request.error);
  });
}

function generateSessionId(url: string): string {
  const random =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().slice(0, 12)
      : Math.random().toString(36).slice(2, 14);
  return `local-${random}-${url.length}`;
}
