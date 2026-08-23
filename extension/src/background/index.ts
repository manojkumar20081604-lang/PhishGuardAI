/**
 * Background Service Worker - Main entry point
 *
 * Message API:
 *   { action: 'analyze', url }  -> { success, data } | { success: false, error }
 *   { action: 'health' }        -> { success, healthy }
 *   { action: 'recentScans', limit? } -> { success, data }
 *   { action: 'clearCache' }    -> { success }
 *   { action: 'trustGet' }      -> { success, data: TrustLists }
 *   { action: 'trustAdd', list, domain }     -> { success, data: TrustLists }
 *   { action: 'trustRemove', list, domain }  -> { success, data: TrustLists }
 *
 * Context menus (Phase F):
 *   link/page right-click -> analyze -> desktop notification
 *   notification click    -> opens popup page pre-scanned with ?url=<target>
 *
 * Password alarm (v3.2): content script reports flagged pages containing
 * password fields via { action: 'notifyPasswordAlarm', data: { url } }
 */

import {
  initBackgroundAPIs,
  analyzeURL,
  listRecentScans,
  clearAllCache,
  checkBackendHealth,
  getTrustLists,
  addTrustEntry,
  removeTrustEntry,
  getVerdictStats,
  resetVerdictStats,
} from './api';
import { recordVerdict } from '../stats/counter';
import { buildScanReportPdf } from '../utils/reportPdf';

/** Uint8Array -> base64 data URL (service-worker safe, no FileReader). */
function bytesToDataUrl(bytes: Uint8Array, mime: string): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return `data:${mime};base64,${btoa(bin)}`;
}

let initialized = false;

async function initialize() {
  if (initialized) return;
  try {
    await initBackgroundAPIs();
    initialized = true;
    console.log('[Background] PhishGuard initialized');
  } catch (error) {
    console.error('[Background] Initialization error:', error);
  }
}

initialize();

// ============================================================================
// TOOLBAR BADGE (Phase E: Auto-Protect)
// ============================================================================

const BADGE_SAFE = '#10b981';
const BADGE_SUSPICIOUS = '#f59e0b';
const BADGE_PHISHING = '#ef4444';

function updateTabBadge(tabId: number, result: { prediction?: string; risk_score?: number }): void {
  try {
    const score = Math.round(Number(result.risk_score ?? 0));
    const pred = String(result.prediction ?? 'safe').toLowerCase();

    const color =
      pred === 'phishing' || score >= 65 ? BADGE_PHISHING
      : pred === 'suspicious' || score >= 35 ? BADGE_SUSPICIOUS
      : BADGE_SAFE;
    const text = color === BADGE_SAFE ? '' : String(Math.min(score, 999));

    chrome.action.setBadgeBackgroundColor({ tabId, color });
    chrome.action.setBadgeText({ tabId, text });
  } catch (error) {
    // Tab may be gone (navigated away/closed mid-analysis) - never crash for a badge
    console.debug('[Background] Badge update skipped:', error);
  }
}

chrome.tabs?.onRemoved?.addListener((tabId) => {
  chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
});

// ============================================================================
// RIGHT-CLICK SCAN (Phase F)
// ============================================================================

const MENU_SCAN_LINK = 'pg-scan-link';
const MENU_SCAN_PAGE = 'pg-scan-page';

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create(
    {
      id: MENU_SCAN_LINK,
      title: '🛡️ Scan this link with PhishGuard',
      contexts: ['link'],
    },
    () => void chrome.runtime.lastError // duplicate id on reload - safe to ignore
  );
  chrome.contextMenus.create(
    {
      id: MENU_SCAN_PAGE,
      title: '🛡️ Scan this page with PhishGuard',
      contexts: ['page', 'frame'],
    },
    () => void chrome.runtime.lastError
  );
});

chrome.contextMenus.onClicked.addListener((info) => {
  const target = info.menuItemId === MENU_SCAN_LINK ? info.linkUrl : info.pageUrl;
  if (!target || !/^https?:/i.test(target)) return;

  console.log('[Background] Context-menu scan:', target);
  void analyzeURL(target)
    .then((result) => notifyVerdict(target, result))
    .catch((error: unknown) => {
      console.error('[Background] Context scan failed:', error);
      notifyError(target, error instanceof Error ? error.message : 'Analysis failed');
    });
});

function verdictTone(result: { prediction?: string; risk_score?: number }): 'phishing' | 'suspicious' | 'safe' {
  const score = Math.round(Number(result.risk_score ?? 0));
  const pred = String(result.prediction ?? 'safe').toLowerCase();
  if (pred === 'phishing' || score >= 65) return 'phishing';
  if (pred === 'suspicious' || score >= 35) return 'suspicious';
  return 'safe';
}

function notifyVerdict(url: string, result: { prediction?: string; risk_score?: number; summary?: string }): void {
  const tone = verdictTone(result);
  const score = Math.round(Number(result.risk_score ?? 0));

  const titles: Record<typeof tone, string> = {
    phishing: `🛑 Dangerous link (risk ${score}/100)`,
    suspicious: `⚠️ Suspicious link (risk ${score}/100)`,
    safe: `✅ Link looks safe (risk ${score}/100)`,
  };

  const detail =
    typeof result.summary === 'string' && result.summary.length > 0
      ? result.summary
      : url;

  chrome.notifications.create(
    {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
      title: titles[tone],
      message: `${url}\n${detail}`.slice(0, 400),
      priority: tone === 'phishing' ? 2 : 1,
    },
    (notificationId) => {
      // Click-through: open the popup page pre-loaded with this URL's result
      const onClicked = (id: string) => {
        if (id !== notificationId) return;
        chrome.notifications.onClicked.removeListener(onClicked);
        chrome.notifications.clear(notificationId, () => void chrome.runtime.lastError);
        chrome.tabs.create({
          url: `${chrome.runtime.getURL('src/popup/popup.html')}?url=${encodeURIComponent(url)}`,
        });
      };
      chrome.notifications.onClicked.addListener(onClicked);
    }
  );
}

function notifyError(url: string, message: string): void {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
    title: '🛡️ PhishGuard could not analyze that link',
    message: `${url}\n${message}`.slice(0, 400),
  });
}

// ============================================================================
// KEYBOARD SHORTCUT (v3.2): Alt+Shift+S / Cmd+Shift+S scans the active tab
// ============================================================================

chrome.commands?.onCommand?.addListener((command) => {
  if (command !== 'scan-current-tab') return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0]?.url;
    if (!url || !/^https?:/i.test(url)) return;
    console.log('[Background] Shortcut scan:', url);
    void analyzeURL(url)
      .then((result) => notifyVerdict(url, result))
      .catch((error: unknown) =>
        notifyError(url, error instanceof Error ? error.message : 'Analysis failed')
      );
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message?.action) {
    case 'analyze': {
      const url: string = message.url;
      if (!url) {
        sendResponse({ success: false, error: 'URL is required' });
        return;
      }
      analyzeURL(url)
        .then((result) => {
          if (sender.tab?.id !== undefined) updateTabBadge(sender.tab.id, result);
          sendResponse({ success: true, data: result });
        })
        .catch((error: unknown) => {
          sendResponse({
            success: false,
            error: error instanceof Error ? error.message : 'Analysis failed',
          });
        });
      return true; // keep channel open for async response
    }

    case 'buildReportPdf': {
      try {
        const bytes = buildScanReportPdf(message.result);
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
        sendResponse({
          success: true,
          dataUrl: bytesToDataUrl(bytes, 'application/pdf'),
          filename: `phishguard-report-${stamp}.pdf`,
        });
      } catch (error: unknown) {
        sendResponse({
          success: false,
          error: error instanceof Error ? error.message : 'PDF build failed',
        });
      }
      return;
    }

    case 'health': {
      checkBackendHealth()
        .then((healthy) => sendResponse({ success: true, healthy }))
        .catch(() => sendResponse({ success: false, healthy: false }));
      return true;
    }

    case 'recentScans': {
      listRecentScans(message.limit ?? 5)
        .then((scans) => sendResponse({ success: true, data: scans }))
        .catch(() => sendResponse({ success: true, data: [] }));
      return true;
    }

    case 'clearCache': {
      clearAllCache()
        .then(() => sendResponse({ success: true }))
        .catch(() => sendResponse({ success: false }));
      return true;
    }

    case 'trustGet': {
      getTrustLists()
        .then((lists) => sendResponse({ success: true, data: lists }))
        .catch((error: unknown) =>
          sendResponse({ success: false, error: error instanceof Error ? error.message : 'failed' })
        );
      return true;
    }

    case 'trustAdd': {
      addTrustEntry(message.list, message.domain)
        .then((lists) => sendResponse({ success: true, data: lists }))
        .catch((error: unknown) =>
          sendResponse({ success: false, error: error instanceof Error ? error.message : 'failed' })
        );
      return true;
    }

    case 'trustRemove': {
      removeTrustEntry(message.list, message.domain)
        .then((lists) => sendResponse({ success: true, data: lists }))
        .catch((error: unknown) =>
          sendResponse({ success: false, error: error instanceof Error ? error.message : 'failed' })
        );
      return true;
    }

    case 'statsGet': {
      getVerdictStats()
        .then((stats) => sendResponse({ success: true, data: stats }))
        .catch(() => sendResponse({ success: false }));
      return true;
    }

    case 'scanMessage': {
      const text: string = message.text;
      if (!text || !text.trim()) {
        sendResponse({ success: false, error: 'Message text is required' });
        return;
      }
      import('../ml/textDetector')
        .then(({ scanMessage }) => scanMessage(text))
        .then((result) => {
          void recordVerdict(result);
          sendResponse({ success: true, data: result });
        })
        .catch((error: unknown) =>
          sendResponse({
            success: false,
            error: error instanceof Error ? error.message : 'Message scan failed',
          })
        );
      return true;
    }

    case 'statsReset': {
      resetVerdictStats()
        .then((stats) => sendResponse({ success: true, data: stats }))
        .catch(() => sendResponse({ success: false }));
      return true;
    }

    case 'notifyPasswordAlarm': {
      const url: string = String(message?.data?.url ?? sender.tab?.url ?? '');
      chrome.notifications.create(
        {
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
          title: '🛑 Password alarm - do not type your password',
          message: `${url}\nPhishGuard flagged this page. Entering credentials here risks theft.`
            .slice(0, 400),
          priority: 2,
        },
        (notificationId) => {
          const onClicked = (id: string) => {
            if (id !== notificationId) return;
            chrome.notifications.onClicked.removeListener(onClicked);
            chrome.notifications.clear(notificationId, () => void chrome.runtime.lastError);
            if (sender.tab?.id !== undefined) {
              chrome.tabs.update(sender.tab.id, { active: true });
            } else if (url && /^https?:/i.test(url)) {
              chrome.tabs.create({
                url: `${chrome.runtime.getURL('src/popup/popup.html')}?url=${encodeURIComponent(url)}`,
              });
            }
          };
          chrome.notifications.onClicked.addListener(onClicked);
        }
      );
      sendResponse({ success: true });
      return true;
    }

    default:
      return undefined; // unrecognized action
  }
});

export {};
