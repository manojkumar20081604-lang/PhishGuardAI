/**
 * PhishGuard AI - Popup Controller
 *
 * ALL analysis goes through the background service worker's local-first
 * pipeline (trust lists -> cache -> ONNX engine). The popup never talks to
 * any server directly.
 */

import { normalizePrediction } from '../services/scanApi';
import type { ScanResult } from '../services/baseApi';
import { get as cacheGet, list as cacheList, clear as cacheClear } from '../db/cache';
import type { ScanCache } from '../db/cache';
import { downloadScanReport } from '../utils/reportPdf';
import { setupDemoController, type DemoController, type DemoStep } from './demo';

// ============================================================================
// DOM ELEMENTS
// ============================================================================

const $ = <T extends HTMLElement = HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

const elements = {
  scanView: $('scan-view'),
  urlInput: $<HTMLInputElement>('url-input'),
  scanBtn: $<HTMLButtonElement>('scan-btn'),
  loadingContainer: $('loading-container'),
  errorContainer: $('error-container'),
  errorMessage: $('error-message'),
  retryBtn: $<HTMLButtonElement>('retry-btn'),
  resultContainer: $('result-container'),
  resultUrl: $('result-url'),
  riskScore: $('risk-score'),
  riskLevelContainer: $('risk-level-container'),
  riskLevelText: $('risk-level-text'),
  explanationSection: $('explanation-section'),
  riskExplanation: $('risk-explanation'),
  rescanBtn: $<HTMLButtonElement>('rescan-btn'),
  detailsBtn: $<HTMLButtonElement>('details-btn'),
  reportBtn: $<HTMLButtonElement>('report-btn'),
  historyBtn: $<HTMLButtonElement>('history-btn'),
  historyContainer: $('history-container'),
  clearHistoryBtn: $<HTMLButtonElement>('clear-history-btn'),
  scanHistoryList: $<HTMLUListElement>('scan-history-list'),
  backToScanBtn: $<HTMLButtonElement>('back-to-scan-btn'),
  closeHistoryBtn: $<HTMLButtonElement>('close-history-btn'),
  modalOverlay: $('modal-overlay'),
  modalTitle: $('modal-title'),
  modalCloseBtn: $<HTMLButtonElement>('modal-close-btn'),
  modalBody: $('modal-body'),
  demoBtn: $<HTMLButtonElement>('demo-btn'),
  demoBanner: $('demo-banner'),
  demoProgressLabel: $('demo-progress-label'),
  demoNote: $('demo-note'),
  demoDots: $('demo-dots'),
  demoStopBtn: $<HTMLButtonElement>('demo-stop-btn'),
};

// ============================================================================
// STATE
// ============================================================================

let lastResult: ScanResult | null = null;
let currentUrl: string | null = null;

const show = (el: HTMLElement): void => el.classList.remove('hidden');
const hide = (el: HTMLElement): void => el.classList.add('hidden');

function hideAllViews(): void {
  [elements.scanView, elements.loadingContainer, elements.errorContainer,
   elements.resultContainer, elements.historyContainer].forEach(hide);
}

// ============================================================================
// VIEW TRANSITIONS
// ============================================================================

function showScanView(): void {
  hideAllViews();
  show(elements.scanView);
}

function showLoading(): void {
  hideAllViews();
  show(elements.loadingContainer);
}

function showError(message: string): void {
  hideAllViews();
  elements.errorMessage.textContent = message;
  show(elements.errorContainer);
}

function showHistory(): void {
  hideAllViews();
  renderHistory();
  show(elements.historyContainer);
}

// ============================================================================
// RENDERING
// ============================================================================

function riskClassFor(score: number): 'safe' | 'warning' | 'danger' {
  if (score >= 65) return 'danger';
  if (score >= 35) return 'warning';
  return 'safe';
}

function labelFor(prediction: string): string {
  switch (normalizePrediction(prediction)) {
    case 'phishing': return 'Phishing';
    case 'suspicious': return 'Suspicious';
    default: return 'Safe';
  }
}

function renderResult(result: ScanResult, opts: { isCached?: boolean } = {}): void {
  lastResult = result;
  hideAllViews();
  show(elements.resultContainer);

  const score = Math.round(Number(result.risk_score ?? 0));
  const cls = riskClassFor(score);

  elements.resultUrl.textContent = result.url || currentUrl || '';
  elements.riskScore.textContent = String(score);

  elements.riskLevelContainer.className = `risk-level ${cls}`;
  elements.riskLevelText.textContent =
    `${labelFor(result.prediction)}${opts.isCached ? ' (cached)' : ''}`;

  const summary = firstString(result.summary);
  const reasons = Array.isArray(result.reasons) ? result.reasons.filter(Boolean) : [];
  if (summary || reasons.length > 0) {
    show(elements.explanationSection);
    elements.riskExplanation.innerHTML = escapeHtml(
      summary || reasons.join(' · ')
    );
  } else {
    hide(elements.explanationSection);
  }
}

function firstString(value: unknown): string {
  return typeof value === 'string' && value.trim().length > 0 ? value : '';
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ============================================================================
// SCANNING
// ============================================================================

async function scanUrl(url: string, opts: { force?: boolean; cachedFirst?: boolean } = {}): Promise<void> {
  currentUrl = url;

  // Optional instant cache-first display (marked "cached"), then fresh verdict
  if (opts.cachedFirst && !opts.force) {
    const cached = await getFromCache(url);
    if (cached) {
      renderResult(cacheToScanResult(cached), { isCached: true });
      void analyzeAndRender(url); // refresh silently in the background
      return;
    }
  }

  showLoading();
  await analyzeAndRender(url);
}

/**
 * Single analysis path: background service worker
 * (trust lists -> cache -> local ONNX -> optional server enrichment).
 * The background already caches results on success.
 */
async function analyzeAndRender(url: string): Promise<void> {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'analyze', url });
    if (!response?.success) {
      throw new Error(response?.error || 'Analysis failed');
    }
    renderResult(response.data as ScanResult);
  } catch (error) {
    const cached = await getFromCache(url);
    if (cached) {
      console.log('[Popup] Engine unavailable, using cached result');
      renderResult(cacheToScanResult(cached), { isCached: true });
      return;
    }
    showError(
      error instanceof Error ? error.message : 'Analysis failed.'
    );
  }
}

async function getFromCache(url: string): Promise<ScanCache | null> {
  try {
    return await cacheGet(url);
  } catch {
    return null;
  }
}

function cacheToScanResult(cached: ScanCache): ScanResult {
  return {
    session_id: cached.session_id,
    url: cached.url,
    prediction: cached.prediction,
    confidence: cached.risk_score / 100,
    risk_score: cached.risk_score,
    risk_level: cached.prediction,
    summary: cached.summary,
    analyzed_at: new Date(cached.timestamp).toISOString(),
  };
}

/** Get the URL of the active tab (plan correction #1: never window.location.href). */
async function getActiveTabUrl(): Promise<string | null> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url ?? null;
  } catch {
    return null;
  }
}

// ============================================================================
// HISTORY
// ============================================================================

async function renderHistory(): Promise<void> {
  let scans: ScanCache[] = [];
  try {
    scans = await cacheList(5); // plan: show last 5 by default
  } catch (error) {
    console.warn('[Popup] History read failed:', error);
  }

  elements.scanHistoryList.innerHTML = '';

  if (scans.length === 0) {
    const li = document.createElement('li');
    li.className = 'empty-state';
    li.textContent = 'No recent scans yet.';
    elements.scanHistoryList.appendChild(li);
    return;
  }

  for (const scan of scans) {
    const li = document.createElement('li');
    li.className = `scan-item ${riskClassFor(scan.risk_score)}`;
    li.innerHTML = `
      <span class="scan-url">${escapeHtml(scan.url)}</span>
      <span class="scan-score ${riskClassFor(scan.risk_score)}">${Math.round(scan.risk_score)}</span>
    `;
    li.addEventListener('click', () => void scanUrl(scan.url, { force: true }));
    elements.scanHistoryList.appendChild(li);
  }
}

// ============================================================================
// DETAILS MODAL
// ============================================================================

function openDetailsModal(): void {
  if (!lastResult) return;
  elements.modalTitle.textContent = 'Analysis Details';

  const rows: Array<[string, string]> = [
    ['URL', lastResult.url || '-'],
    ['Prediction', labelFor(lastResult.prediction)],
    ['Risk Score', `${Math.round(Number(lastResult.risk_score ?? 0))}/100`],
    ['Confidence', `${Math.round((Number(lastResult.confidence ?? 0)) * 100)}%`],
    ['Analyzed At', lastResult.analyzed_at ? new Date(lastResult.analyzed_at).toLocaleString() : '-'],
  ];

  const breakdownEntries = Object.entries(lastResult.risk_breakdown ?? {});
  const reasons = Array.isArray(lastResult.reasons) ? lastResult.reasons.filter(Boolean) : [];
  const tips = Array.isArray(lastResult.security_tips) ? lastResult.security_tips.filter(Boolean) : [];

  const section = (title: string, items: string[]): string =>
    items.length === 0
      ? ''
      : `<h3>${escapeHtml(title)}</h3><ul>${items.map((i) => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`;

  elements.modalBody.innerHTML = `
    <table class="details-table">
      ${rows.map(([k, v]) => `<tr><td><strong>${escapeHtml(k)}</strong></td><td>${escapeHtml(v)}</td></tr>`).join('')}
    </table>
    ${section('Risk Factors', reasons)}
    ${section('Security Tips', tips)}
    ${breakdownEntries.length === 0 ? '' : `
      <h3>Risk Breakdown</h3>
      <table class="details-table">
        ${breakdownEntries.map(([k, v]) => `<tr><td><strong>${escapeHtml(k)}</strong></td><td>${escapeHtml(String(v))}</td></tr>`).join('')}
      </table>
    `}
  `;

  show(elements.modalOverlay);
}

function closeModal(): void {
  hide(elements.modalOverlay);
}

// ============================================================================
// EVENT WIRING & INITIALIZATION
// ============================================================================

function wireEvents(): void {
  wireUrlScanEvents();
  wireMessageScanEvents();
  wireResultButtons();
  setupDemoMode();
}

function wireUrlScanEvents(): void {
  elements.scanBtn.addEventListener('click', () => {
    const url = elements.urlInput.value.trim();
    if (!url || !url.includes('.')) {
      showError('Please enter a valid URL including the domain.');
      return;
    }
    void scanUrl(url, { force: true });
  });

  elements.retryBtn.addEventListener('click', () => {
    if (currentUrl) void scanUrl(currentUrl, { force: true });
    else showScanView();
  });

  elements.rescanBtn.addEventListener('click', () => {
    if (currentUrl) void scanUrl(currentUrl, { force: true });
  });

  elements.detailsBtn.addEventListener('click', openDetailsModal);

  elements.reportBtn.addEventListener('click', () => {
    if (lastResult) downloadScanReport(lastResult);
  });

  elements.modalCloseBtn.addEventListener('click', closeModal);
  elements.modalOverlay.addEventListener('click', (event) => {
    if (event.target === elements.modalOverlay) closeModal();
  });
}

// ============================================================================
// MESSAGE SCAN TAB (Phase H)
// ============================================================================

function wireMessageScanEvents(): void {
  const tabUrl = document.getElementById('tab-url')!;
  const tabMsg = document.getElementById('tab-message')!;
  const urlControls = document.getElementById('url-scan-controls')!;
  const msgControls = document.getElementById('message-scan-controls')!;
  const urlHint = document.getElementById('url-mode-hint')!;
  const msgInput = document.getElementById('msg-input') as HTMLTextAreaElement;
  const typeHint = document.getElementById('msg-type-hint')!;

  // Popups auto-close when focus moves elsewhere (e.g. to copy an email),
  // which kills in-progress pastes. Offer the same UI as a real tab.
  const openTabBtn = document.getElementById('open-tab-btn');
  openTabBtn?.addEventListener('click', () => {
    void chrome.tabs.create({
      url: `${location.href.split('?')[0]}?asPage=1&tab=message`,
    });
    window.close();
  });

  function selectTab(which: 'url' | 'message'): void {
    tabUrl.classList.toggle('active', which === 'url');
    tabMsg.classList.toggle('active', which === 'message');
    urlControls.classList.toggle('hidden', which !== 'url');
    msgControls.classList.toggle('hidden', which === 'url');
    urlHint.classList.toggle('hidden', which === 'url');
  }
  selectTab('url');

  tabUrl.addEventListener('click', () => selectTab('url'));
  tabMsg.addEventListener('click', () => selectTab('message'));

  msgInput.addEventListener('input', () => {
    const text = msgInput.value.trim();
    if (!text) {
      typeHint.textContent = 'Detected: —';
      return;
    }
    // Same heuristic as the engine: header markers or long + email mention = email
    const isEmail =
      /^from:|^subject:/im.test(text) ||
      (/[\w.-]+@[\w.-]+\.\w+/.test(text) && text.length > 200);
    const chars = msgInput.value.length.toLocaleString();
    typeHint.textContent = `Detected: ${isEmail ? '📧 Email' : '📱 SMS/text'} · ${chars} characters (full text is analyzed)`;
  });

  document.getElementById('msg-scan-btn')!.addEventListener('click', () => void scanMessageFlow());
}

async function scanMessageFlow(): Promise<void> {
  const input = document.getElementById('msg-input') as HTMLTextAreaElement;
  const text = input.value.trim();

  if (!text) {
    showError('Paste an email or SMS message to analyze.');
    return;
  }

  showLoading();

  try {
    const response = await chrome.runtime.sendMessage({ action: 'scanMessage', text });
    if (!response?.success) {
      throw new Error(response?.error || 'Message scan failed');
    }
    renderResult(messageToScanResult(response.data));
  } catch (error) {
    showError(error instanceof Error ? error.message : 'Message scan failed.');
  }
}

/** Adapt MessageScanResult into the shared result view shape. */
function messageToScanResult(msg: {
  prediction: string;
  confidence: number;
  risk_score: number;
  detected_type: string;
  reasons: string[];
  security_tips: string[];
  summary: string;
}): Parameters<typeof renderResult>[0] {
  const firstLine = (document.getElementById('msg-input') as HTMLTextAreaElement)
    .value.trim()
    .split('\n')[0] ?? '';

  return {
    session_id: `msg-${Date.now().toString(36)}`,
    url: `${msg.detected_type === 'email' ? '📧 Email' : '📱 SMS'} · ${firstLine.slice(0, 64)}${firstLine.length > 64 ? '…' : ''}`,
    prediction: msg.prediction,
    confidence: msg.confidence,
    risk_score: msg.risk_score,
    risk_level: String(msg.prediction).toUpperCase(),
    reasons: msg.reasons,
    summary: msg.summary,
    security_tips: msg.security_tips,
    analyzed_at: new Date().toISOString(),
  };
}

// ============================================================================
// COMPETITION DEMO MODE
// ============================================================================

let demoController: DemoController | null = null;

/** Run one scripted scenario through the REAL pipeline and render it. */
async function runDemoStep(step: DemoStep): Promise<{ prediction: string }> {
  if (step.kind === 'url') {
    const response = await chrome.runtime.sendMessage({ action: 'analyze', url: step.payload });
    if (!response?.success) throw new Error(response?.error || 'Analysis failed');
    const data = response.data as ScanResult;
    renderResult(data);
    return { prediction: String(data.prediction) };
  }

  const response = await chrome.runtime.sendMessage({ action: 'scanMessage', text: step.payload });
  if (!response?.success) throw new Error(response?.error || 'Message scan failed');
  const msg = response.data as {
    prediction: string; confidence: number; risk_score: number;
    detected_type: string; reasons: string[]; security_tips: string[]; summary: string;
  };
  const firstLine = step.payload.split('\n')[0] ?? '';
  const adapted: ScanResult = {
    session_id: `demo-msg-${Date.now().toString(36)}`,
    url: `${msg.detected_type === 'email' ? '📧 Email' : '📱 SMS'} · ${firstLine.slice(0, 64)}${firstLine.length > 64 ? '…' : ''}`,
    prediction: msg.prediction,
    confidence: msg.confidence,
    risk_score: msg.risk_score,
    risk_level: String(msg.prediction).toUpperCase(),
    reasons: msg.reasons,
    summary: msg.summary,
    security_tips: msg.security_tips,
    analyzed_at: new Date().toISOString(),
  };
  renderResult(adapted);
  return { prediction: String(msg.prediction) };
}

function showDemoProgress(index: number, total: number, step: DemoStep): void {
  hideAllViews();
  show(elements.resultContainer); // renderResult will re-show per verdict
  show(elements.demoBanner);
  elements.demoStopBtn.classList.remove('hidden');
  elements.demoNote.classList.remove('hidden');
  elements.demoDots.classList.remove('hidden');

  elements.demoProgressLabel.textContent = `▶ Demo ${index + 1}/${total} · ${step.label}`;
  elements.demoNote.textContent = step.note;
  elements.demoDots.innerHTML = '';
  for (let i = 0; i < total; i++) {
    const dot = document.createElement('span');
    dot.className = `demo-dot${i === index ? ' active' : ''}${i < index ? ' done' : ''}`;
    elements.demoDots.appendChild(dot);
  }
}

function finishDemo(ran: number, total: number, caught: number, stopped: boolean): void {
  if (ran === 0 && stopped) {
    hide(elements.demoBanner);
    showScanView();
    return;
  }
  elements.demoStopBtn.classList.add('hidden');
  elements.demoDots.classList.add('hidden');
  elements.demoNote.classList.add('hidden');
  elements.demoProgressLabel.textContent = stopped
    ? `⏹ Demo stopped after ${ran}/${total}`
    : `✅ Demo complete — ${caught}/${ran} scenarios matched expectations`;
  // Let the summary breathe, then return to a clean scan view.
  setTimeout(() => {
    hide(elements.demoBanner);
    showScanView();
  }, 3400);
}

function setupDemoMode(): void {
  demoController = setupDemoController({
    runStep: runDemoStep,
    showProgress: showDemoProgress,
    finish: finishDemo,
  });
  elements.demoBtn.addEventListener('click', () => void demoController?.start());
  elements.demoStopBtn.addEventListener('click', () => demoController?.stop());
}

function wireResultButtons(): void {
  elements.historyBtn.addEventListener('click', () => void showHistory());
  elements.backToScanBtn.addEventListener('click', showScanView);
  elements.closeHistoryBtn.addEventListener('click', async () => {
    try {
      await cacheClear();
      console.log('[Popup] History cleared');
    } catch (error) {
      console.warn('[Popup] Clear history failed:', error);
    }
    showScanView();
  });
}

async function init(): Promise<void> {
  const params = new URLSearchParams(location.search);

  // Opened as a real browser tab (not the toolbar popup)
  if (params.get('asPage') === '1') {
    document.body.classList.add('as-page');
    document.getElementById('open-tab-btn')?.classList.add('hidden');
  }

  wireEvents();
  void loadStatsStrip();

  // Context-menu/notification flow may preset the target URL (Phase F)
  const preset = params.get('url');

  if (preset && /^https?:/i.test(preset)) {
    await scanUrl(preset, { cachedFirst: true });
    return;
  }

  // Full-tab mode with Message Scanner pre-selected (?tab=message)
  if (params.get('tab') === 'message') {
    showScanView();
    document.getElementById('tab-message')?.click();
    document.querySelector<HTMLTextAreaElement>('#msg-input')?.focus();
    return;
  }

  // Auto-scan the page the user is viewing
  const tabUrl = await getActiveTabUrl();
  if (tabUrl && /^https?:/i.test(tabUrl)) {
    await scanUrl(tabUrl, { cachedFirst: true });
  } else {
    showScanView();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  void init();
});

// ============================================================================
// STATS STRIP (Phase G)
// ============================================================================

interface StatsPayload {
  totalScans: number;
  byDay: Record<string, { scans: number; threats: number }>;
}

async function loadStatsStrip(): Promise<void> {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'statsGet' });
    if (!response?.success) return;
    const stats = response.data as StatsPayload;

    let weekThreats = 0;
    for (let i = 0; i < 7; i++) {
      const key = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      weekThreats += stats.byDay?.[key]?.threats ?? 0;
    }

    const strip = document.getElementById('stats-strip');
    const threatsEl = document.getElementById('stats-threats-week');
    const totalEl = document.getElementById('stats-scans-total');
    if (strip && threatsEl && totalEl) {
      threatsEl.textContent = String(weekThreats);
      totalEl.textContent = String(stats.totalScans ?? 0);
      strip.classList.remove('hidden');
    }
  } catch {
    // stats are cosmetic - never block popup on them
  }
}
