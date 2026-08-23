/**
 * Options Page Logic - Settings management and cache statistics
 */

import { set, get, list, clear as cacheClear, isDbReady } from '../db/cache';
import { normalizeDomain } from '../trust/lists';
import { ScanApiClient, MetricsApiClient, DEFAULT_BASE_URL } from '../services';

// ============================================================================
// GLOBAL STATE
// ============================================================================

let currentUrl = null;
let currentResult = null;
let isCached = false;

// ============================================================================
// INITIALIZATION
// ============================================================================

window.PGAI = {
  init: async () => {
    console.log('[Options] Initializing PhishGuard options page...');

    // Load saved settings from storage
    await window.PGAI.loadSavedSettings();

    // Initialize cache database
    await initCache();

    // Load and display current cache statistics
    await window.PGAI.refreshStats();

    // Setup event listeners
    setupEventListeners();

    // Load Auto-Protect settings into the UI
    await loadProtectSettings();
    document
      .getElementById('save-protect-btn')
      ?.addEventListener('click', () => saveProtectSettings());

    // Statistics dashboard (Phase G)
    await loadStatsDashboard();
    document
      .getElementById('stats-reset-btn')
      ?.addEventListener('click', () => resetStatsUI());

    // Model-age indicator (v3.2)
    renderExtensionVersion();
    await loadModelAge();
  },

  /**
   * Save settings to storage
   */
  async saveSettings() {
    try {
      const safeThreshold = parseInt(document.getElementById('safeThreshold').value);
      const suspiciousThreshold = parseInt(document.getElementById('suspiciousThreshold').value);
      const maxCacheSize = parseInt(document.getElementById('maxCacheSize').value);
      
      // Save to chrome storage
      await chrome.storage.local.set({
        'phishguard_safe_threshold': safeThreshold,
        'phishguard_suspicious_threshold': suspiciousThreshold,
        'phishguard_max_cache_size': maxCacheSize
      });

      console.log('[Options] Settings saved successfully');
      
      // Show success message
      showStatus('success', 'Settings saved!');
    } catch (error) {
      console.error('[Options] Save settings failed:', error);
      showStatus('error', 'Failed to save settings.');
    }
  },

  /**
   * Load settings from storage
   */
  async loadSavedSettings() {
    try {
      const saved = await chrome.storage.local.get([
        'phishguard_safe_threshold',
        'phishguard_suspicious_threshold',
        'phishguard_max_cache_size'
      ]);

      // Apply saved values to UI
      if (saved.phishguard_safe_threshold) {
        document.getElementById('safeThreshold').value = saved.phishguard_safe_threshold;
        updateSliderValue('safeThreshold', saved.phishguard_safe_threshold);
      }

      if (saved.phishguard_suspicious_threshold) {
        document.getElementById('suspiciousThreshold').value = saved.phishguard_suspicious_threshold;
        updateSliderValue('suspiciousThreshold', saved.phishguard_suspicious_threshold);
      }

      if (saved.phishguard_max_cache_size) {
        document.getElementById('maxCacheSize').value = saved.phishguard_max_cache_size;
      }

      console.log('[Options] Settings loaded from storage');
    } catch (error) {
      console.error('[Options] Load settings failed:', error);
    }
  },

  /**
   * Clear cache
   */
  async clearCache() {
    try {
      await cacheClear();
      
      // Update stats
      await window.PGAI.refreshStats();
      
      showStatus('success', 'Cache cleared successfully!');
    } catch (error) {
      console.error('[Options] Clear cache failed:', error);
      showStatus('error', 'Failed to clear cache.');
    }
  },

  /**
   * Check backend health
   */
  async checkBackendHealth() {
    try {
      const healthy = await metricsApi.isBackendAvailable();

      if (healthy) {
        showStatus('success', 'Backend is healthy!');
      } else {
        showStatus('error', 'Backend is unavailable.');
      }

      return healthy;
    } catch (error) {
      console.error('[Options] Health check failed:', error);
      showStatus('error', 'Failed to check backend health.');
      return null;
    }
  },

  /**
   * Refresh cache statistics
   */
  async refreshStats() {
    let totalScans = 0;
    try {
      const scans = await list(100); // Get up to 100 for stats

      totalScans = scans.length;
      const cachedScans = totalScans; // All loaded scans are from cache

      // Update UI
      document.getElementById('totalScansStat').textContent = totalScans.toLocaleString();
      document.getElementById('cachedScansStat').textContent = cachedScans.toLocaleString();

      console.log('[Options] Stats refreshed:', { totalScans, cachedScans });
      return { totalScans, cachedScans };
    } catch (error) {
      console.error('[Options] Refresh stats failed:', error);

      // Reset to 0 on error
      document.getElementById('totalScansStat').textContent = '0';
      document.getElementById('cachedScansStat').textContent = '0';
    }

    return { totalScans, cachedScans: 0 };
  },

  /**
   * Get recent scans for display
   */
  async getRecentScans(limit = 5) {
    try {
      const scans = await list(limit);
      
      // Format for display
      return scans.map(scan => ({
        url: scan.url,
        risk_score: scan.risk_score,
        prediction: scan.prediction,
        timestamp: new Date(scan.timestamp).toLocaleString(),
        isCached: true
      }));
    } catch (error) {
      console.error('[Options] Get recent scans failed:', error);
      return [];
    }
  },

  /**
   * Export cache as JSON file
   */
  async exportCache() {
    try {
      const scans = await list(100); // Export up to 100
      
      if (scans.length === 0) {
        showStatus('error', 'No cached data to export.');
        return;
      }

      const blob = new Blob([JSON.stringify(scans, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishguard-cache-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      
      console.log('[Options] Cache exported successfully');
      showStatus('success', 'Cache exported as JSON file!');
    } catch (error) {
      console.error('[Options] Export cache failed:', error);
      showStatus('error', 'Failed to export cache.');
    }
  },

  /**
   * Export settings bundle (settings + trust lists + stats) as JSON file
   */
  async exportSettings() {
    try {
      const [settingsStored, listsResponse, statsResponse] = await Promise.all([
        chrome.storage.local.get('phishguard_settings'),
        chrome.runtime.sendMessage({ action: 'trustGet' }),
        chrome.runtime.sendMessage({ action: 'statsGet' })
      ]);

      const bundle = {
        app: 'phishguard-ai',
        kind: 'settings-bundle',
        version: 1,
        exportedAt: new Date().toISOString(),
        settings: settingsStored.phishguard_settings || {},
        trustLists: listsResponse?.success
          ? listsResponse.data
          : { trusted: [], blocked: [] },
        stats: statsResponse?.success ? statsResponse.data : null
      };

      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishguard-settings-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);

      console.log('[Options] Settings bundle exported');
      showStatus('success', 'Settings exported (includes trust lists & stats).');
    } catch (error) {
      console.error('[Options] Export settings failed:', error);
      showStatus('error', 'Failed to export settings.');
    }
  },

  /**
   * Import a settings bundle exported by exportSettings()
   */
  async importSettings(file) {
    try {
      const bundle = JSON.parse(await file.text());
      if (bundle?.app !== 'phishguard-ai' || bundle?.kind !== 'settings-bundle') {
        showStatus('error', 'That file is not a PhishGuard settings export.');
        return;
      }
      if (!confirm(
        'Importing will REPLACE your current Auto-Protect settings, trust lists, and statistics.\n\nContinue?'
      )) {
        return;
      }

      if (bundle.settings && typeof bundle.settings === 'object') {
        await chrome.storage.local.set({ phishguard_settings: bundle.settings });
      }

      if (
        Array.isArray(bundle.trustLists?.trusted) &&
        Array.isArray(bundle.trustLists?.blocked)
      ) {
        const clean = (domains) => [
          ...new Set(domains.map((d) => normalizeDomain(String(d))).filter(Boolean))
        ].sort();
        await chrome.storage.local.set({
          pgai_trust_lists: {
            trusted: clean(bundle.trustLists.trusted),
            blocked: clean(bundle.trustLists.blocked)
          }
        });
      }

      if (bundle.stats && typeof bundle.stats === 'object') {
        const num = (v) => Math.max(0, Math.floor(Number(v) || 0));
        const byDay = {};
        for (const [key, day] of Object.entries(bundle.stats.byDay || {})) {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(key)) continue;
          byDay[key] = { scans: num(day?.scans), threats: num(day?.threats) };
        }
        await chrome.storage.local.set({
          pgai_stats: {
            totalScans: num(bundle.stats.totalScans),
            phishingBlocked: num(bundle.stats.phishingBlocked),
            suspiciousSeen: num(bundle.stats.suspiciousSeen),
            safeVisits: num(bundle.stats.safeVisits),
            byDay,
            updatedAt: new Date().toISOString()
          }
        });
      }

      await loadProtectSettings();
      await renderTrustLists();
      await loadStatsDashboard();

      console.log('[Options] Settings bundle imported');
      showStatus('success', 'Settings imported successfully!');
    } catch (error) {
      console.error('[Options] Import settings failed:', error);
      showStatus('error', 'Import failed: invalid or corrupted file.');
    }
  },

  /**
   * Get current cache size in bytes
   */
  async getCacheSize() {
    try {
      const scans = await list(100);
      
      let totalBytes = 0;
      for (const scan of scans) {
        // Rough estimate: ~500-800 bytes per scan entry
        totalBytes += 600; 
      }

      return Math.round(totalBytes / 1024 * 100) / 100; // Return in KB
    } catch (error) {
      console.error('[Options] Get cache size failed:', error);
      return 0;
    }
  },

  /**
   * Analyze URL from popup (for testing)
   */
  async analyzeUrl(url) {
    if (!url) {
      showStatus('error', 'No URL provided.');
      return null;
    }

    try {
      // Check cache first
      const cached = await getFromCache(url);
      
      if (cached) {
        console.log('[Options] Using cached result for:', url);
        currentUrl = url;
        isCached = true;
        window.PGAI.renderResult(cached, { isCached: true });
        return cached;
      }

      // Perform fresh analysis
      currentUrl = url;

      const result = await scanApi.analyze(url);

      // Cache the result AFTER successful API call (correction #4)
      await set(url, {
        session_id: result.session_id,
        url: result.url,
        risk_score: result.risk_score,
        prediction: result.prediction,
        summary: typeof result.summary === 'string' ? result.summary : undefined
      });

      currentResult = result;
      isCached = false;
      
      window.PGAI.renderResult(result);
      
      return result;
    } catch (error) {
      console.error('[Options] Analysis failed:', error);
      showStatus('error', error.message || 'Failed to analyze URL.');
      return null;
    }
  },

  /**
   * Render analysis result in options page
   */
  renderResult(result, options = {}) {
    // Create result display container if not exists
    let resultContainer = document.getElementById('resultDisplay');
    
    if (!resultContainer) {
      resultContainer = document.createElement('div');
      resultContainer.id = 'resultDisplay';
      resultContainer.style.cssText = `
        background: #f8f9fa;
        border-radius: 8px;
        padding: 15px;
        margin-top: 15px;
        font-size: 13px;
      `;
      
      const container = document.querySelector('.container');
      if (container) {
        container.insertBefore(resultContainer, document.getElementById('statusMessage'));
      }
    }

    // Update result display
    resultContainer.innerHTML = `
      <div style="font-weight: 600; color: #333; margin-bottom: 8px;">${result.url}</div>
      <div style="background: ${getRiskColor(result.prediction)}; padding: 10px; border-radius: 6px; font-size: 14px;">
        <strong>${getPredictionText(result.prediction)}</strong> • Risk Score: ${Math.round(result.risk_score || 0)}/100
      </div>
      ${result.explanation ? `<div style="margin-top: 8px; color: #666;">${result.explanation}</div>` : ''}
    `;

    console.log('[Options] Result rendered:', result);
  }
};

// ============================================================================
// API CLIENTS (Singleton instances)
// ============================================================================

const scanApi = new ScanApiClient(DEFAULT_BASE_URL);
const metricsApi = new MetricsApiClient(DEFAULT_BASE_URL);

// ============================================================================
// CACHE INITIALIZATION
// ============================================================================

async function initCache() {
  try {
    await isDbReady();
    console.log('[Options] Cache database initialized');
  } catch (error) {
    console.error('[Options] Cache initialization failed:', error);
    showStatus('error', 'Cache unavailable: ' + (error.message || 'Unknown error'));
  }
}

async function getFromCache(url) {
  try {
    const cached = await get(url);
    
    if (cached) {
      console.log('[Options] Cache hit for:', url);
      return {
        ...cached,
        timestamp: new Date(cached.timestamp),
        isCached: true
      };
    }
  } catch (error) {
    console.error('[Options] Get from cache failed:', error);
  }

  return null;
}

// ============================================================================
// UI HELPERS
// ============================================================================

function updateSliderValue(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

function getRiskColor(prediction) {
  const colors = {
    safe: '#E8F5E9',
    suspicious: '#FFF8E1',
    phishing: '#FFEBEE'
  };
  
  return colors[prediction] || colors.safe;
}

function getPredictionText(prediction) {
  const texts = {
    safe: 'Safe',
    suspicious: 'Suspicious',
    phishing: 'Phishing'
  };
  
  return texts[prediction] || 'Unknown';
}

function showStatus(type, message) {
  const statusEl = document.getElementById('statusMessage');
  if (!statusEl) return;

  statusEl.className = `status-message ${type}`;
  statusEl.style.display = 'block';
  statusEl.textContent = message;

  // Auto-hide after 5 seconds for success messages
  if (type === 'success') {
    setTimeout(() => {
      statusEl.style.display = 'none';
    }, 5000);
  }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
  setupTrustLists();
  // Slider value updates
  document.getElementById('safeThreshold').addEventListener('input', (e) => {
    updateSliderValue('safeThreshold', e.target.value);
  });

  document.getElementById('suspiciousThreshold').addEventListener('input', (e) => {
    updateSliderValue('suspiciousThreshold', e.target.value);
  });

  // Toggle switches
  const cacheToggle = document.getElementById('cacheToggle');
  if (cacheToggle) {
    cacheToggle.addEventListener('click', () => {
      cacheToggle.classList.toggle('active');
      
      const isEnabled = cacheToggle.classList.contains('active');
      console.log('[Options] Cache enabled:', isEnabled);
    });
  }

  const autoRetryToggle = document.getElementById('autoRetryToggle');
  if (autoRetryToggle) {
    autoRetryToggle.addEventListener('click', () => {
      autoRetryToggle.classList.toggle('active');
      
      const isEnabled = autoRetryToggle.classList.contains('active');
      console.log('[Options] Auto-retry enabled:', isEnabled);
    });
  }

  // Buttons
  document.getElementById('clearCacheBtn').addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear all cached scans?')) {
      await window.PGAI.clearCache();
    }
  });

  document.getElementById('checkBackendBtn').addEventListener('click', async () => {
    await window.PGAI.checkBackendHealth();
  });

  document.getElementById('refreshStatsBtn').addEventListener('click', async () => {
    await window.PGAI.refreshStats();
  });

  // Save settings button (add to DOM if needed)
  const saveSettingsBtn = document.createElement('button');
  saveSettingsBtn.id = 'saveSettingsBtn';
  saveSettingsBtn.className = 'btn btn-primary';
  saveSettingsBtn.style.cssText = `
    width: 100%;
    margin-top: 15px;
    padding: 12px 24px;
    background: #667eea;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    cursor: pointer;
  `;
  saveSettingsBtn.textContent = 'Save Settings';
  
  saveSettingsBtn.addEventListener('click', () => {
    window.PGAI.saveSettings();
  });

  // Add to container if not exists
  const container = document.querySelector('.container');
  if (container && !document.getElementById('saveSettingsBtn')) {
    container.appendChild(saveSettingsBtn);
  }

  // Export cache button
  const exportCacheBtn = document.createElement('button');
  exportCacheBtn.id = 'exportCacheBtn';
  exportCacheBtn.className = 'btn btn-secondary';
  exportCacheBtn.style.cssText = `
    width: 100%;
    margin-top: 15px;
    padding: 12px 24px;
    background: #e0e0e0;
    color: #333;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    cursor: pointer;
  `;
  exportCacheBtn.textContent = 'Export Cache as JSON';
  
  exportCacheBtn.addEventListener('click', () => {
    window.PGAI.exportCache();
  });

  if (container && !document.getElementById('exportCacheBtn')) {
    container.appendChild(exportCacheBtn);
  }

  // Settings bundle export/import (v3.2)
  document
    .getElementById('export-settings-btn')
    ?.addEventListener('click', () => window.PGAI.exportSettings());

  const importFile = document.getElementById('import-settings-file');
  document
    .getElementById('import-settings-btn')
    ?.addEventListener('click', () => importFile?.click());
  importFile?.addEventListener('change', () => {
    const file = importFile.files?.[0];
    if (file) void window.PGAI.importSettings(file);
    importFile.value = '';
  });
}

// ============================================================================
// MODEL-AGE INDICATOR (v3.2)
// ============================================================================

function renderExtensionVersion() {
  const el = document.getElementById('ext-version');
  try {
    if (el) el.textContent = chrome.runtime.getManifest().version;
  } catch {
    if (el) el.textContent = '3.2.0';
  }
}

const MODEL_FRESH_DAYS = 90;
const MODEL_STALE_DAYS = 180;

async function loadModelAge() {
  const el = document.getElementById('model-age');
  if (!el) return;

  try {
    const res = await fetch(chrome.runtime.getURL('models/url-model-v3-meta.json'));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const meta = await res.json();

    const trainedAt = String(meta?.dataset?.trained_at || '');
    const trainedMs = Date.parse(`${trainedAt}T00:00:00Z`);
    if (!trainedAt || Number.isNaN(trainedMs)) throw new Error('no trained_at');

    const days = Math.max(0, Math.floor((Date.now() - trainedMs) / 86400000));
    const [color, label] =
      days < MODEL_FRESH_DAYS
        ? ['#10b981', 'fresh']
        : days < MODEL_STALE_DAYS
          ? ['#f59e0b', 'consider retraining']
          : ['#ef4444', 'STALE - retrain recommended'];

    el.innerHTML =
      `<span style="color:${color}; font-weight:700;">&#9679;</span> ` +
      `${escapeHtmlText(String(meta.name || 'url-model'))} &middot; ` +
      `${escapeHtmlText(String(meta.algorithm || '?'))} &middot; ` +
      `trained ${escapeHtmlText(trainedAt)} (${days} day${days === 1 ? '' : 's'} ago, ${label})`;
    el.style.color = 'rgba(255, 255, 255, 0.9)';
  } catch (error) {
    console.warn('[Options] Model age unavailable:', error);
    el.innerHTML = '<span style="color:#ef4444;">&#9679;</span> Model metadata unavailable';
    el.style.color = 'rgba(255, 255, 255, 0.7)';
  }
}

function escapeHtmlText(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ============================================================================
// AUTO-INIT ON LOAD
// ============================================================================

window.addEventListener('load', () => {
  window.PGAI.init();
});

// ============================================================================
// TRUST LISTS (Phase D)
// ============================================================================

function setupTrustLists() {
  const trustedInput = document.getElementById('trusted-input');
  const blockedInput = document.getElementById('blocked-input');

  document.getElementById('trusted-add-btn')?.addEventListener('click', () => {
    void trustAdd('trusted', trustedInput.value);
    trustedInput.value = '';
  });
  trustedInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      void trustAdd('trusted', trustedInput.value);
      trustedInput.value = '';
    }
  });

  document.getElementById('blocked-add-btn')?.addEventListener('click', () => {
    void trustAdd('blocked', blockedInput.value);
    blockedInput.value = '';
  });
  blockedInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      void trustAdd('blocked', blockedInput.value);
      blockedInput.value = '';
    }
  });

  renderTrustLists();
}

async function trustAdd(list, rawDomain) {
  if (!rawDomain || !rawDomain.trim()) return;
  const response = await chrome.runtime.sendMessage({
    action: 'trustAdd',
    list,
    domain: rawDomain.trim()
  });
  if (!response?.success) {
    showStatus('error', response?.error || 'Invalid domain');
    return;
  }
  renderTrustListsFrom(response.data);
}

async function trustRemove(list, domain) {
  const response = await chrome.runtime.sendMessage({
    action: 'trustRemove',
    list,
    domain
  });
  if (response?.success) renderTrustListsFrom(response.data);
}

async function renderTrustLists() {
  const response = await chrome.runtime.sendMessage({ action: 'trustGet' });
  if (response?.success) renderTrustListsFrom(response.data);
}

function renderTrustListsFrom(lists) {
  renderOneList('trusted-list', lists.trusted);
  renderOneList('blocked-list', lists.blocked);
}

function renderOneList(elementId, domains) {
  const ul = document.getElementById(elementId);
  if (!ul) return;
  ul.innerHTML = '';

  if (!domains.length) {
    const li = document.createElement('li');
    li.className = 'trust-list-empty';
    li.textContent = 'No domains yet';
    ul.appendChild(li);
    return;
  }

  for (const domain of domains) {
    const li = document.createElement('li');
    const span = document.createElement('span');
    span.textContent = domain;
    const btn = document.createElement('button');
    btn.className = 'trust-remove';
    btn.textContent = '\u00d7';
    btn.title = `Remove ${domain}`;
    btn.addEventListener('click', () => {
      const listName = elementId.startsWith('trusted') ? 'trusted' : 'blocked';
      void trustRemove(listName, domain);
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

// ============================================================================
// AUTO-PROTECT SETTINGS (Phase E)
// ============================================================================

async function loadProtectSettings() {
  try {
    const stored = await chrome.storage.local.get('phishguard_settings');
    const s = stored.phishguard_settings || {};
    document.getElementById('protect-level').value = s.autoProtectLevel || 'suspicious';
    document.getElementById('block-high-risk').checked = s.blockHighRiskPages !== false;
  } catch (error) {
    console.error('[Options] Load protect settings failed:', error);
  }
}

async function saveProtectSettings() {
  const level = document.getElementById('protect-level').value;
  const blockHighRiskPages = document.getElementById('block-high-risk').checked;

  try {
    const stored = await chrome.storage.local.get('phishguard_settings');
    const merged = {
      ...(stored.phishguard_settings || {}),
      autoProtectLevel: level,
      blockHighRiskPages
    };
    await chrome.storage.local.set({ phishguard_settings: merged });
    showStatus('success', 'Auto-Protect settings saved!');
  } catch (error) {
    console.error('[Options] Save protect settings failed:', error);
    showStatus('error', 'Failed to save Auto-Protect settings.');
  }
}

// ============================================================================
// STATISTICS DASHBOARD (Phase G)
// ============================================================================

const CHART_COLORS = { threats: '#ef4444', safe: '#3b82f6' };
const DONUT_COLORS = { phishing: '#ef4444', suspicious: '#f59e0b', safe: '#10b981' };

async function loadStatsDashboard() {
  const response = await chrome.runtime.sendMessage({ action: 'statsGet' });
  if (!response?.success) return;
  renderStats(response.data);
}

function renderStats(stats) {
  document.getElementById('stat-total').textContent = Number(stats.totalScans || 0).toLocaleString();
  document.getElementById('stat-phishing').textContent = Number(stats.phishingBlocked || 0).toLocaleString();
  document.getElementById('stat-suspicious').textContent = Number(stats.suspiciousSeen || 0).toLocaleString();
  document.getElementById('stat-safe').textContent = Number(stats.safeVisits || 0).toLocaleString();

  renderDailyChart(stats.byDay || {});
  renderDonut(stats);
}

function renderDailyChart(byDay) {
  const svg = document.getElementById('stats-chart');
  if (!svg) return;

  const days = [];
  for (let i = 13; i >= 0; i--) {
    const key = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    days.push({ key, label: key.slice(8), ...(byDay[key] || { scans: 0, threats: 0 }) });
  }
  const max = Math.max(1, ...days.map((d) => d.scans));

  const W = 560, H = 170, padB = 22, padT = 10;
  const chartH = H - padB - padT;
  const bw = W / days.length;

  let inner = '';
  // gridline at max
  inner += `<line x1="0" y1="${padT}" x2="${W}" y2="${padT}" stroke="rgba(255,255,255,0.12)" stroke-dasharray="3 3"/>`;

  days.forEach((d, i) => {
    const x = i * bw + bw * 0.18;
    const w = bw * 0.64;
    const hSafe = ((d.scans - d.threats) / max) * chartH;
    const hThreat = (d.threats / max) * chartH;
    const ySafe = H - padB - hSafe;
    const yThreat = ySafe - hThreat;

    if (d.scans > 0) {
      inner += `<rect x="${x}" y="${ySafe}" width="${w}" height="${Math.max(hSafe, 1)}" fill="${CHART_COLORS.safe}" rx="2"><title>${d.key}: ${d.scans} scans (${d.threats} threats)</title></rect>`;
      if (d.threats > 0) {
        inner += `<rect x="${x}" y="${yThreat}" width="${w}" height="${Math.max(hThreat, 1)}" fill="${CHART_COLORS.threats}" rx="2"><title>${d.key}: ${d.threats} threats</title></rect>`;
      }
    }
    if (i % 2 === 0) {
      inner += `<text x="${x + w / 2}" y="${H - 6}" font-size="9" fill="rgba(255,255,255,0.45)" text-anchor="middle">${d.label}</text>`;
    }
  });

  svg.innerHTML = inner;
}

function renderDonut(stats) {
  const svg = document.getElementById('stats-donut');
  const legend = document.getElementById('donut-legend');
  if (!svg || !legend) return;

  const total = Math.max(1,
    Number(stats.phishingBlocked || 0) +
    Number(stats.suspiciousSeen || 0) +
    Number(stats.safeVisits || 0));

  const segs = [
    { name: 'Threats flagged', value: stats.phishingBlocked || 0, color: DONUT_COLORS.phishing },
    { name: 'Suspicious', value: stats.suspiciousSeen || 0, color: DONUT_COLORS.suspicious },
    { name: 'Safe', value: stats.safeVisits || 0, color: DONUT_COLORS.safe },
  ];

  const R = 44, C = 2 * Math.PI * R;
  let offset = 0;
  let inner = `
    <circle cx="60" cy="60" r="${R}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="14"/>`;

  for (const seg of segs) {
    if (seg.value <= 0) continue;
    const frac = seg.value / total;
    inner += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${seg.color}" stroke-width="14"
      stroke-dasharray="${(frac * C).toFixed(2)} ${C.toFixed(2)}"
      stroke-dashoffset="${(-offset * C).toFixed(2)}"
      transform="rotate(-90 60 60)"><title>${seg.name}: ${seg.value}</title></circle>`;
    offset += frac;
  }

  inner += `<text x="60" y="65" font-size="16" font-weight="700" fill="#fff" text-anchor="middle">${total === 1 ? stats.totalScans : total}</text>`;
  svg.innerHTML = inner;

  legend.innerHTML = segs
    .map((s) => `<div><span class="dot" style="background:${s.color}"></span>${s.name}: <strong>${Number(s.value).toLocaleString()}</strong></div>`)
    .join('');
}

async function resetStatsUI() {
  if (!confirm('Reset all PhishGuard statistics? Scan history is not affected.')) return;
  const response = await chrome.runtime.sendMessage({ action: 'statsReset' });
  if (response?.success) {
    renderStats(response.data);
    showStatus('success', 'Statistics reset.');
  } else {
    showStatus('error', 'Failed to reset statistics.');
  }
}
