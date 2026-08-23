/**
 * PhishGuard AI - Content Script
 * Injected into all pages for real-time analysis and UI injection.
 * All risk analysis comes from the Flask backend via the background service worker.
 */

import { downloadScanReport, type ScanResultForReport } from '../utils/reportPdf';

// ============================================================================
// PDF REPORT (password-alarm / warning surfaces)
// ============================================================================

/** Adapt the injected-UI verdict shape into the report generator's input. */
function uiToScanResult(ui: any): ScanResultForReport {
  return {
    session_id: `cs-${Date.now().toString(36)}`,
    url: window.location.href,
    prediction: String(ui.finalPrediction ?? 'safe').toLowerCase(),
    confidence: Number(ui.finalConfidence ?? 0) / 100,
    risk_score: Number(ui.finalRiskScore ?? 0),
    risk_level: String(ui.finalThreatLevel ?? '').toUpperCase(),
    reasons: Array.isArray(ui.explanation?.riskIndicators) ? ui.explanation.riskIndicators : [],
    summary: typeof ui.explanation?.summary === 'string' ? ui.explanation.summary : '',
    security_tips: Array.isArray(ui.explanation?.recommendations) ? ui.explanation.recommendations : [],
    recommendation: '',
    analyzed_at: ui.analyzedAt || new Date().toISOString(),
  };
}

// ============================================================================
// BACKEND ANALYSIS BRIDGE
// ============================================================================

/** Ask the background service worker to analyze a URL against the Flask backend. */
function requestBackendAnalysis(url: string): Promise<any> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action: 'analyze', url }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (response && response.success && response.data) {
        resolve(response.data);
      } else {
        reject(new Error(response?.error || 'Analysis failed'));
      }
    });
  });
}

/** Map a backend ScanResult into the shape the injected UI expects. */
function mapScanResult(result: any): any {
  const score = Number(result.risk_score ?? 0);
  const prediction = String(result.prediction ?? 'safe').toLowerCase();
  const finalPrediction =
    prediction === 'phishing' ? 'Phishing' : prediction === 'suspicious' ? 'Suspicious' : 'Safe';
  const threatLevel =
    prediction === 'phishing' ? 'High' : prediction === 'suspicious' ? 'Medium' : 'Low';
  const confidence = Number(result.confidence ?? 0);

  return {
    finalPrediction,
    finalConfidence: confidence > 1 ? Math.round(confidence) : Math.round(confidence * 100),
    finalRiskScore: score,
    finalThreatLevel: threatLevel,
    sources: { local: false, backend: true, threatIntel: false },
    explanation: {
      summary: result.summary || '',
      riskIndicators: Array.isArray(result.reasons) ? result.reasons : [],
      recommendations: Array.isArray(result.security_tips) ? result.security_tips : [],
      breakdown: {
        backendScore: score,
      },
    },
    analyzedAt: result.analyzed_at || new Date().toISOString(),
    isCached: Boolean(result.isCached),
  };
}

// Listen for messages from background/popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'showAnalysis':
      showAnalysisUI(message.data);
      sendResponse({ success: true });
      break;
      
    case 'showWarning':
      showWarningBanner(message.data);
      sendResponse({ success: true });
      break;
      
    case 'injectUI':
      injectPhishGuardButton(message.data);
      sendResponse({ success: true });
      break;
      
    case 'getPageInfo':
      sendResponse(getPageInfo());
      break;
      
    case 'analyzePage':
      analyzeCurrentPage().then(result => sendResponse(result));
      return true; // Async
  }
  
  return true;
});

// Get page information for analysis
function getPageInfo(): any {
  return {
    url: window.location.href,
    title: document.title,
    domain: window.location.hostname,
    forms: getFormsInfo(),
    links: getLinksInfo(),
    scripts: getScriptsInfo(),
    iframes: getIframesInfo(),
    meta: getMetaInfo(),
    textContent: document.body?.innerText?.substring(0, 5000) || ''
  };
}

// Extract form information
function getFormsInfo(): any[] {
  const forms = Array.from(document.forms);
  return forms.map(form => ({
    action: form.action,
    method: form.method,
    inputs: Array.from(form.elements).map(el => ({
      type: (el as HTMLInputElement).type,
      name: (el as HTMLInputElement).name,
      id: el.id,
      value: (el as HTMLInputElement).type === 'password' ? '[REDACTED]' : (el as HTMLInputElement).value
    }))
  }));
}

// Extract links information
function getLinksInfo(): any[] {
  const links = Array.from(document.querySelectorAll('a[href]'));
  return links.slice(0, 50).map(link => ({
    href: (link as HTMLAnchorElement).href,
    text: link.textContent?.trim().substring(0, 100),
    target: (link as HTMLAnchorElement).target,
    rel: (link as HTMLAnchorElement).rel
  }));
}

// Extract scripts information
function getScriptsInfo(): any[] {
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  return scripts.map(script => ({
    src: (script as HTMLScriptElement).src,
    async: (script as HTMLScriptElement).async,
    defer: (script as HTMLScriptElement).defer
  }));
}

// Extract iframes information
function getIframesInfo(): any[] {
  const iframes = Array.from(document.querySelectorAll('iframe[src]'));
  return iframes.map(iframe => ({
    src: (iframe as HTMLIFrameElement).src,
    width: (iframe as HTMLIFrameElement).width,
    height: (iframe as HTMLIFrameElement).height
  }));
}

// Extract meta information
function getMetaInfo(): any {
  const metas = Array.from(document.querySelectorAll('meta'));
  const info: any = {};
  metas.forEach(meta => {
    if (meta.name) info[meta.name] = meta.content;
    const ogProperty = meta.getAttribute('property');
    if (ogProperty) info[ogProperty] = meta.content;
  });
  return info;
}

// Analyze current page via backend, enriched with local DOM checks
async function analyzeCurrentPage(): Promise<any> {
  const pageInfo = getPageInfo();

  // Check forms for login/password fields (pure DOM check)
  const hasLoginForm = pageInfo.forms.some((form: any) =>
    form.inputs.some((input: any) => input.type === 'password') ||
    form.inputs.some((input: any) => /user|email|login|signin/i.test(input.name || ''))
  );

  try {
    const backendResult = mapScanResult(await requestBackendAnalysis(pageInfo.url));

    const combinedReasons = [
      ...backendResult.explanation.riskIndicators,
      ...(hasLoginForm ? ['Login form detected on page'] : []),
    ];

    if (hasLoginForm && !combinedReasons.includes('Login form detected on page')) {
      combinedReasons.push('Login form detected on page');
    }

    return {
      ...backendResult,
      explanation: {
        ...backendResult.explanation,
        riskIndicators: combinedReasons,
        recommendations:
          hasLoginForm && backendResult.finalThreatLevel !== 'Low'
            ? ['DO NOT enter credentials on this page', ...backendResult.explanation.recommendations]
            : backendResult.explanation.recommendations,
      },
      pageInfo: {
        hasLoginForm,
        formsCount: pageInfo.forms.length,
        linksCount: pageInfo.links.length,
        scriptsCount: pageInfo.scripts.length,
        iframesCount: pageInfo.iframes.length
      }
    };
  } catch (error) {
    // Backend unreachable: degrade gracefully with local DOM signals only
    return {
      finalPrediction: 'Unknown',
      finalConfidence: 0,
      finalRiskScore: 0,
      finalThreatLevel: 'Unknown',
      sources: { local: true, backend: false, threatIntel: false },
      explanation: {
        summary: 'Backend unavailable - only basic page checks were performed.',
        riskIndicators: [
          ...(hasLoginForm ? ['Login form detected on page'] : [])
        ],
        recommendations: [
          'Verify the site authenticity before entering sensitive data'
        ],
        breakdown: {}
      },
      analyzedAt: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
      pageInfo: {
        hasLoginForm,
        formsCount: pageInfo.forms.length,
        linksCount: pageInfo.links.length,
        scriptsCount: pageInfo.scripts.length,
        iframesCount: pageInfo.iframes.length
      }
    };
  }
}

// Inject PhishGuard floating button
function injectPhishGuardButton(data?: any): void {
  if (document.getElementById('phishguard-float-btn')) return;
  
  const btn = document.createElement('div');
  btn.id = 'phishguard-float-btn';
  btn.innerHTML = `
    <style>
      #phishguard-float-btn {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 56px;
        height: 56px;
        border-radius: 28px;
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        box-shadow: 0 4px 20px rgba(30, 58, 138, 0.4);
        cursor: pointer;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: transform 0.2s, box-shadow 0.2s;
        border: none;
      }
      #phishguard-float-btn:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 28px rgba(30, 58, 138, 0.5);
      }
      #phishguard-float-btn.phishguard-safe { background: linear-gradient(135deg, #065f46 0%, #10b981 100%); }
      #phishguard-float-btn.phishguard-suspicious { background: linear-gradient(135deg, #92400e 0%, #f59e0b 100%); }
      #phishguard-float-btn.phishguard-phishing { background: linear-gradient(135deg, #991b1b 0%, #ef4444 100%); animation: phishguard-pulse 2s infinite; }
      @keyframes phishguard-pulse { 0%, 100% { box-shadow: 0 4px 20px rgba(239, 68, 68, 0.4); } 50% { box-shadow: 0 4px 30px rgba(239, 68, 68, 0.7); } }
      #phishguard-float-btn svg { width: 28px; height: 28px; color: white; }
      #phishguard-tooltip {
        position: absolute;
        bottom: 70px;
        right: 0;
        background: #1e293b;
        color: white;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        white-space: nowrap;
        opacity: 0;
        visibility: hidden;
        transition: opacity 0.2s, visibility 0.2s;
        pointer-events: none;
      }
      #phishguard-float-btn:hover #phishguard-tooltip {
        opacity: 1;
        visibility: visible;
      }
    </style>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
      <path d="M9 12l2 2 4-4"></path>
    </svg>
    <div id="phishguard-tooltip">PhishGuard AI - Click to analyze</div>
  `;
  
  // Set initial state based on data or analyze current page
  if (data) {
    updateButtonState(btn, data.finalThreatLevel);
  } else {
    updateButtonState(btn, 'Low');
    requestBackendAnalysis(window.location.href)
      .then((result) => {
        if (document.getElementById('phishguard-float-btn')) {
          updateButtonState(btn, mapScanResult(result).finalThreatLevel);
        }
      })
      .catch(() => { /* keep neutral state */ });
  }

  btn.addEventListener('click', () => {
    // Request full analysis from backend via background
    chrome.runtime.sendMessage({ action: 'analyze', url: window.location.href }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) return;
      showAnalysisUI(response.data);
      updateButtonState(btn, response.data.finalThreatLevel);
    });
  });

  document.body.appendChild(btn);
}

// Update button appearance based on threat level
function updateButtonState(btn: HTMLElement, threatLevel: string): void {
  btn.className = 'phishguard-float-btn';
  switch (threatLevel) {
    case 'High':
      btn.classList.add('phishguard-phishing');
      btn.querySelector('#phishguard-tooltip')!.textContent = '⚠ Phishing detected - Click for details';
      break;
    case 'Medium':
      btn.classList.add('phishguard-suspicious');
      btn.querySelector('#phishguard-tooltip')!.textContent = '⚠ Suspicious - Click for details';
      break;
    case 'Low':
    default:
      btn.classList.add('phishguard-safe');
      btn.querySelector('#phishguard-tooltip')!.textContent = '✓ Safe - Click to re-analyze';
      break;
  }
}

// Show analysis results in a modal
function showAnalysisUI(result: any): void {
  // Remove existing modal
  const existing = document.getElementById('phishguard-modal');
  if (existing) existing.remove();
  
  const modal = document.createElement('div');
  modal.id = 'phishguard-modal';
  modal.innerHTML = `
    <style>
      #phishguard-modal-overlay {
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        animation: phishguard-fade-in 0.2s ease;
      }
      /* While the analysis modal is open, keep warning surfaces out of the way */
      body.pgai-modal-open #pgai-suspicious-chip,
      body.pgai-modal-open #pgai-pw-alarm,
      body.pgai-modal-open #phishguard-float-btn,
      body.pgai-modal-open .phishguard-badge { visibility: hidden !important; }
      @keyframes phishguard-fade-in { from { opacity: 0; } to { opacity: 1; } }
      #phishguard-modal {
        background: #1e293b;
        border-radius: 16px;
        padding: 0;
        max-width: 520px;
        width: 90%;
        max-height: 85vh;
        overflow: hidden;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        border: 1px solid #334155;
        animation: phishguard-slide-up 0.3s ease;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      @keyframes phishguard-slide-up { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
      .phishguard-header {
        padding: 20px 24px;
        border-bottom: 1px solid #334155;
        display: flex;
        align-items: center;
        justify-content: space-between;
      }
      .phishguard-header h2 { margin: 0; font-size: 18px; font-weight: 600; color: #f1f5f9; }
      .phishguard-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 13px;
        font-weight: 600;
      }
      .phishguard-badge.phishing { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
      .phishguard-badge.suspicious { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
      .phishguard-badge.safe { background: rgba(16, 185, 129, 0.2); color: #10b981; }
      .phishguard-close {
        background: none;
        border: none;
        color: #94a3b8;
        cursor: pointer;
        padding: 8px;
        border-radius: 8px;
        transition: background 0.2s, color 0.2s;
      }
      .phishguard-close:hover { background: #334155; color: #f1f5f9; }
      .phishguard-content { padding: 24px; overflow-y: auto; max-height: 60vh; }
      .phishguard-section { margin-bottom: 24px; }
      .phishguard-section:last-child { margin-bottom: 0; }
      .phishguard-section-title { font-size: 14px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px; }
      .phishguard-score { display: flex; align-items: center; gap: 16px; }
      .phishguard-score-circle {
        width: 80px;
        height: 80px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
      }
      .phishguard-score-circle svg { width: 80px; height: 80px; transform: rotate(-90deg); }
      .phishguard-score-circle circle { fill: none; stroke-width: 6; }
      .phishguard-score-circle .bg { stroke: #334155; }
      .phishguard-score-circle .progress { stroke-linecap: round; transition: stroke-dashoffset 0.5s ease; }
      .phishguard-score-value { position: absolute; font-size: 24px; font-weight: 700; color: #f1f5f9; }
      .phishguard-score-label { color: #94a3b8; font-size: 14px; }
      .phishguard-reasons { list-style: none; padding: 0; margin: 0; }
      .phishguard-reasons li { display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px; background: #0f172a; border-radius: 8px; margin-bottom: 8px; color: #e2e8f0; font-size: 14px; line-height: 1.5; }
      .phishguard-reasons li:last-child { margin-bottom: 0; }
      .phishguard-reasons .icon { flex-shrink: 0; width: 20px; height: 20px; color: currentColor; }
      .phishguard-recommendations { display: flex; flex-direction: column; gap: 10px; }
      .phishguard-recommendation { display: flex; align-items: flex-start; gap: 10px; padding: 12px; background: #0f172a; border-radius: 8px; color: #e2e8f0; font-size: 14px; line-height: 1.5; border-left: 3px solid; }
      .phishguard-recommendation.high { border-left-color: #ef4444; }
      .phishguard-recommendation.medium { border-left-color: #f59e0b; }
      .phishguard-recommendation.low { border-left-color: #10b981; }
      .phishguard-breakdown { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
      .phishguard-breakdown-item { background: #0f172a; padding: 14px; border-radius: 8px; }
      .phishguard-breakdown-label { font-size: 12px; color: #94a3b8; margin-bottom: 4px; }
      .phishguard-breakdown-value { font-size: 20px; font-weight: 700; color: #f1f5f9; }
      .phishguard-actions { display: flex; gap: 10px; padding-top: 16px; border-top: 1px solid #334155; }
      .phishguard-btn { flex: 1; padding: 12px 16px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: none; transition: opacity 0.2s; }
      .phishguard-btn:hover { opacity: 0.9; }
      .phishguard-btn-primary { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; }
      .phishguard-btn-secondary { background: #334155; color: #e2e8f0; }
    </style>
    <div id="phishguard-modal-overlay">
      <div id="phishguard-modal">
        <div class="phishguard-header">
          <h2>PhishGuard AI Analysis</h2>
          <span class="phishguard-badge ${result.finalPrediction.toLowerCase()}">
            ${getBadgeIcon(result.finalPrediction)} ${result.finalPrediction}
          </span>
        </div>
        <div class="phishguard-content">
          <div class="phishguard-section">
            <div class="phishguard-section-title">Risk Score</div>
            <div class="phishguard-score">
              <div class="phishguard-score-circle">
                <svg viewBox="0 0 80 80">
                  <circle class="bg" cx="40" cy="40" r="34"></circle>
                  <circle class="progress ${getProgressClass(result.finalThreatLevel)}" 
                    cx="40" cy="40" r="34"
                    stroke-dasharray="213.6"
                    stroke-dashoffset="${getProgressOffset(result.finalRiskScore)}">
                  </circle>
                </svg>
                <span class="phishguard-score-value">${result.finalRiskScore}</span>
              </div>
              <div>
                <div class="phishguard-score-label">Threat Level: <strong style="color: ${getThreatColor(result.finalThreatLevel)}">${result.finalThreatLevel}</strong></div>
                <div class="phishguard-score-label">Confidence: <strong>${result.finalConfidence}%</strong></div>
                <div class="phishguard-score-label">Sources: ${getSourcesText(result.sources)}</div>
              </div>
            </div>
          </div>
          
          ${result.explanation.riskIndicators && result.explanation.riskIndicators.length > 0 ? `
          <div class="phishguard-section">
            <div class="phishguard-section-title">Risk Indicators</div>
            <ul class="phishguard-reasons">
              ${result.explanation.riskIndicators.map((reason: string) => `
                <li>
                  <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                  </svg>
                  ${reason}
                </li>
              `).join('')}
            </ul>
          </div>
          ` : ''}
          
          <div class="phishguard-section">
            <div class="phishguard-section-title">Recommendations</div>
            <div class="phishguard-recommendations">
              ${result.explanation.recommendations?.map((rec: string, i: number) => `
                <div class="phishguard-recommendation ${result.finalThreatLevel.toLowerCase()}">
                  <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 18 15 12 9 6"></polyline>
                  </svg>
                  ${rec}
                </div>
              `).join('') || ''}
            </div>
          </div>
          
          ${result.explanation.breakdown ? `
          <div class="phishguard-section">
            <div class="phishguard-section-title">Score Breakdown</div>
            <div class="phishguard-breakdown">
              ${result.explanation.breakdown.localScore !== undefined ? `
              <div class="phishguard-breakdown-item">
                <div class="phishguard-breakdown-label">Local Analysis</div>
                <div class="phishguard-breakdown-value">${result.explanation.breakdown.localScore}</div>
              </div>
              ` : ''}
              ${result.explanation.breakdown.backendScore !== undefined ? `
              <div class="phishguard-breakdown-item">
                <div class="phishguard-breakdown-label">Backend ML</div>
                <div class="phishguard-breakdown-value">${result.explanation.breakdown.backendScore}</div>
              </div>
              ` : ''}
              ${result.explanation.breakdown.threatIntelScore !== undefined ? `
              <div class="phishguard-breakdown-item">
                <div class="phishguard-breakdown-label">Threat Intel</div>
                <div class="phishguard-breakdown-value">${result.explanation.breakdown.threatIntelScore}</div>
              </div>
              ` : ''}
              <div class="phishguard-breakdown-item">
                <div class="phishguard-breakdown-label">Final Score</div>
                <div class="phishguard-breakdown-value">${result.finalRiskScore}</div>
              </div>
            </div>
          </div>
          ` : ''}
          
          <div class="phishguard-actions">
            <button class="phishguard-btn phishguard-btn-secondary" id="phishguard-close-modal">Close</button>
            <button class="phishguard-btn phishguard-btn-primary" id="phishguard-report">Report False Positive</button>
          </div>
        </div>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  document.body.classList.add('pgai-modal-open');

  const closeAnalysisModal = () => {
    modal.remove();
    document.body.classList.remove('pgai-modal-open');
    document.removeEventListener('keydown', handleEsc);
  };

  // Event listeners
  modal.querySelector('#phishguard-close-modal')!.addEventListener('click', closeAnalysisModal);
  modal.querySelector('#phishguard-modal-overlay')!.addEventListener('click', (e) => {
    if (e.target === modal.querySelector('#phishguard-modal-overlay')) closeAnalysisModal();
  });
  modal.querySelector('#phishguard-report')!.addEventListener('click', () => {
    // Send feedback to background
    chrome.runtime.sendMessage({
      action: 'reportFeedback',
      data: { url: window.location.href, prediction: result.finalPrediction, correct: false }
    });
    alert('Thank you for reporting! This helps improve PhishGuard AI.');
    closeAnalysisModal();
  });
  
  // Close on Escape
  const handleEsc = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      closeAnalysisModal();
    }
  };
  document.addEventListener('keydown', handleEsc);
}

// Show warning banner at top of page
function showWarningBanner(data: any): void {
  const existing = document.getElementById('phishguard-warning-banner');
  if (existing) existing.remove();
  
  // Tone drives styling; accept either prediction names or legacy levels
  const predLower = String(data.prediction ?? '').toLowerCase();
  const levelLower = String(data.level ?? '').toLowerCase();
  const tone = predLower.includes('phish') || levelLower === 'high' ? 'phishing' : 'suspicious';

  const banner = document.createElement('div');
  banner.id = 'phishguard-warning-banner';
  const bannerScore = typeof data.score === 'number' ? Math.round(data.score) : null;
  banner.innerHTML = `
    <style>
      #phishguard-warning-banner {
        position: fixed;
        top: 0; left: 0; right: 0;
        z-index: 2147483647;
        padding: 16px 22px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 15px;
        line-height: 1.5;
        animation: phishguard-slide-down 0.3s ease, phishguard-banner-glow 2.2s ease-in-out .4s infinite;
        box-shadow: 0 6px 26px rgba(0, 0, 0, 0.4);
      }
      @keyframes phishguard-slide-down { from { transform: translateY(-100%); } to { transform: translateY(0); } }
      @keyframes phishguard-banner-glow {
        0%, 100% { filter: brightness(1); }
        50%      { filter: brightness(1.14); }
      }
      #phishguard-warning-banner.phishing { background: linear-gradient(135deg, #7f1d1d 0%, #b91c1c 55%, #ef4444 100%); color: white; border-bottom: 3px solid #fecaca; }
      #phishguard-warning-banner.suspicious { background: linear-gradient(135deg, #451a03 0%, #92400e 55%, #f59e0b 100%); color: white; border-bottom: 3px solid #fde68a; }
      .phishguard-banner-content { max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
      .phishguard-banner-text { display: flex; align-items: center; gap: 14px; flex: 1; min-width: 300px; }
      .phishguard-banner-iconwrap {
        width: 46px; height: 46px; flex-shrink: 0; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        background: rgba(255,255,255,.16); border: 2px solid rgba(255,255,255,.55); font-size: 24px;
      }
      .phishguard-banner-headline {
        display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
        font-size: 17.5px; font-weight: 800; letter-spacing: .05em; line-height: 1.25;
      }
      .phishguard-banner-scorechip {
        background: rgba(0,0,0,.35); border: 1px solid rgba(255,255,255,.5);
        padding: 3px 11px; border-radius: 999px; font-size: 12.5px; font-weight: 800; letter-spacing: .02em;
      }
      .phishguard-banner-sub { font-size: 13.5px; opacity: .95; margin-top: 3px; }
      .phishguard-banner-actions { display: flex; gap: 8px; flex-shrink: 0; }
      .phishguard-banner-btn { padding: 9px 18px; border-radius: 8px; font-size: 13.5px; font-weight: 700; cursor: pointer; border: none; transition: opacity 0.2s; }
      .phishguard-banner-btn:hover { opacity: 0.9; }
      .phishguard-banner-btn-primary { background: white; color: #991b1b; }
      .phishguard-banner-btn-secondary { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); }
      .phishguard-banner-btn-suspicious-primary { background: white; color: #92400e; }
      .phishguard-banner-btn-suspicious-secondary { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); }
    </style>
    <div class="phishguard-banner-content">
      <div class="phishguard-banner-text">
        <span class="phishguard-banner-iconwrap">${tone === 'phishing' ? '&#9940;' : '&#9888;'}</span>
        <div>
          <div class="phishguard-banner-headline">
            ${data.prediction} PAGE FLAGGED
            ${bannerScore !== null ? `<span class="phishguard-banner-scorechip">RISK ${bannerScore}/100</span>` : ''}
          </div>
          <div class="phishguard-banner-sub"><strong>PhishGuard AI:</strong> ${data.message}</div>
        </div>
      </div>
      <div class="phishguard-banner-actions">
        <button class="phishguard-banner-btn phishguard-banner-btn-${data.level.toLowerCase()}-primary" id="phishguard-banner-analyze">View Details</button>
        <button class="phishguard-banner-btn phishguard-banner-btn-${data.level.toLowerCase()}-secondary" id="phishguard-banner-dismiss">Dismiss</button>
      </div>
    </div>
  `;
  
  banner.className = tone;
  document.body.insertBefore(banner, document.body.firstChild);
  
  // Adjust page content to not hide behind banner
  document.body.style.paddingTop = banner.offsetHeight + 'px';
  
  const btnBase = tone === 'phishing' ? '' : '-suspicious';
  const analyzeBtn = banner.querySelector('#phishguard-banner-analyze') as HTMLButtonElement;
  analyzeBtn.className = `phishguard-banner-btn phishguard-banner-btn${btnBase}-primary`;
  const dismissBtn = banner.querySelector('#phishguard-banner-dismiss') as HTMLButtonElement;
  dismissBtn.className = `phishguard-banner-btn phishguard-banner-btn${btnBase}-secondary`;

  analyzeBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'analyze', url: window.location.href }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) return;
      showAnalysisUI(response.data);
    });
    markDismissedThisVisit();
    banner.remove();
    document.body.style.paddingTop = '';
  });
  
  dismissBtn.addEventListener('click', () => {
    markDismissedThisVisit();
    banner.remove();
    document.body.style.paddingTop = '';
  });
}

// ============================================================================
// AUTO-PROTECT (Phase E)
// ============================================================================

type ProtectLevel = 'off' | 'suspicious' | 'all';

interface ProtectSettings {
  autoProtectLevel: ProtectLevel;
  blockHighRiskPages: boolean;
}

const PROTECT_DEFAULTS: ProtectSettings = {
  autoProtectLevel: 'suspicious',
  blockHighRiskPages: true,
};

async function getProtectSettings(): Promise<ProtectSettings> {
  try {
    const stored = await chrome.storage.local.get('phishguard_settings');
    return { ...PROTECT_DEFAULTS, ...(stored.phishguard_settings ?? {}) };
  } catch {
    return { ...PROTECT_DEFAULTS };
  }
}

function markDismissedThisVisit(): void {
  try {
    sessionStorage.setItem(`pgai-dismissed:${window.location.href}`, '1');
  } catch { /* storage may be unavailable */ }
}

function isDismissedThisVisit(): boolean {
  try {
    return sessionStorage.getItem(`pgai-dismissed:${window.location.href}`) === '1';
  } catch {
    return false;
  }
}

/** Silent on-load protection sweep. Trust/cache/engine handled by background. */
async function runAutoProtect(): Promise<void> {
  const settings = await getProtectSettings();

  // Legacy floating shield behavior preserved independently of protect level
  chrome.storage.local.get('phishguard_settings', (result) => {
    const s = result.phishguard_settings || {};
    if (s.showBadge !== false && s.autoAnalyze !== false && !document.getElementById('phishguard-float-btn')) {
      injectPhishGuardButton();
    }
  });

  if (settings.autoProtectLevel === 'off') return;
  if (!/^https?:/i.test(window.location.href)) return;

  try {
    const raw = await requestBackendAnalysis(window.location.href);
    applyAutoProtectVerdict(mapScanResult(raw), settings);
  } catch {
    // Analysis unavailable (engine loading/offline edge): stay silent, never break pages
  }
}

function applyAutoProtectVerdict(
  ui: ReturnType<typeof mapScanResult>,
  settings: ProtectSettings
): void {
  armPasswordAlarm(ui);
  if (isDismissedThisVisit()) return;

  if (ui.finalPrediction === 'Phishing') {
    showWarningBanner({
      prediction: 'PHISHING',
      level: 'HIGH',
      score: ui.finalRiskScore,
      message: ui.explanation.summary || 'Strong phishing indicators detected on this page.',
    });
    if (settings.blockHighRiskPages && ui.finalRiskScore >= 85) {
      showBlockPage(ui);
    }
  } else if (ui.finalPrediction === 'Suspicious') {
    showSuspiciousChip(ui);
  }
  // Safe -> nothing visible (badge on toolbar only)
}

/** Full-screen interstitial for very high-confidence phishing pages. */
function showBlockPage(ui: ReturnType<typeof mapScanResult>): void {
  if (document.getElementById('pgai-block-page')) return;

  const reasons = (ui.explanation.riskIndicators ?? []).slice(0, 4) as string[];
  const overlay = document.createElement('div');
  overlay.id = 'pgai-block-page';
  overlay.innerHTML = `
    <style>
      #pgai-block-page {
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(5, 8, 20, 0.96);
        display: flex; align-items: center; justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      #pgai-block-card {
        max-width: 520px; width: 90%;
        background: #161b2e; border: 1px solid #ef4444;
        border-radius: 16px; padding: 32px; color: #f1f5f9;
        box-shadow: 0 25px 60px rgba(239, 68, 68, 0.25);
      }
      #pgai-block-card h1 { margin: 0 0 6px; font-size: 22px; color: #ef4444; }
      #pgai-block-url { color: #94a3b8; font-size: 13px; word-break: break-all; margin-bottom: 16px; }
      .pgai-block-reasons { margin: 0 0 20px; padding-left: 18px; color: #e2e8f0; font-size: 14px; line-height: 1.7; }
      .pgai-block-actions { display: flex; gap: 12px; align-items: center; }
      #pgai-go-back {
        flex: 1; padding: 12px 18px; border: none; border-radius: 10px;
        background: linear-gradient(135deg, #3b82f6, #2563eb);
        color: white; font-size: 15px; font-weight: 700; cursor: pointer;
      }
      #pgai-continue {
        background: none; border: none; color: #64748b; font-size: 13px;
        cursor: pointer; text-decoration: underline;
      }
    </style>
    <div id="pgai-block-card">
      <h1>&#9940; Dangerous page blocked</h1>
      <div id="pgai-block-url">${escapeHtmlAttr(window.location.href)}</div>
      <ul class="pgai-block-reasons">
        ${reasons.map((r) => `<li>${escapeHtmlAttr(String(r))}</li>`).join('')}
        <li><strong>Risk score: ${ui.finalRiskScore}/100</strong></li>
      </ul>
      <div class="pgai-block-actions">
        <button id="pgai-go-back">Go back to safety</button>
        <button id="pgai-continue">Continue anyway</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(overlay);

  overlay.querySelector('#pgai-go-back')!.addEventListener('click', () => {
    markDismissedThisVisit();
    if (history.length > 1) {
      history.back();
    } else {
      window.location.href = 'about:blank';
    }
  });
  overlay.querySelector('#pgai-continue')!.addEventListener('click', () => {
    markDismissedThisVisit();
    overlay.remove();
  });
}

/** Small non-intrusive corner chip for suspicious pages. */
function showSuspiciousChip(ui: ReturnType<typeof mapScanResult>): void {
  if (document.getElementById('pgai-suspicious-chip')) return;

  const reasons = ((ui.explanation.riskIndicators ?? []) as string[]).slice(0, 2);
  const chip = document.createElement('div');
  chip.id = 'pgai-suspicious-chip';
  chip.innerHTML = `
    <style>
      #pgai-suspicious-chip {
        position: fixed; bottom: 84px; left: 20px; z-index: 2147483646;
        width: min(340px, calc(100vw - 40px));
        background: linear-gradient(150deg, #451a03 0%, #78350f 55%, #92400e 100%);
        color: #fff; border-radius: 16px; cursor: pointer;
        border: 1px solid rgba(251, 191, 36, .45);
        box-shadow: 0 12px 34px rgba(0,0,0,.4), 0 0 0 0 rgba(245,158,11,.55);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        padding: 14px 16px;
        animation: pgai-chip-in .28s ease, pgai-chip-glow 2.4s ease-in-out .5s infinite;
      }
      @keyframes pgai-chip-in { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
      @keyframes pgai-chip-glow {
        0%, 100% { box-shadow: 0 12px 34px rgba(0,0,0,.4), 0 0 0 0 rgba(245,158,11,.5); }
        50%      { box-shadow: 0 12px 34px rgba(0,0,0,.4), 0 0 22px 4px rgba(245,158,11,.35); }
      }
      #pgai-suspicious-chip:hover { transform: translateY(-2px); transition: transform .15s ease; }
      .pgai-sc-head { display: flex; align-items: center; gap: 10px; }
      .pgai-sc-ico {
        width: 34px; height: 34px; flex-shrink: 0; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        background: rgba(251,191,36,.18); border: 1.5px solid rgba(251,191,36,.7);
        font-size: 17px;
      }
      .pgai-sc-title { font-size: 15px; font-weight: 800; letter-spacing: .04em; line-height: 1.2; }
      .pgai-sc-sub { font-size: 11.5px; opacity: .85; margin-top: 2px; }
      .pgai-sc-score {
        margin-left: auto; background: rgba(0,0,0,.35); border: 1px solid rgba(251,191,36,.5);
        padding: 3px 9px; border-radius: 999px; font-size: 12px; font-weight: 800; white-space: nowrap;
      }
      .pgai-sc-body { margin-top: 10px; font-size: 12.5px; line-height: 1.5; opacity: .95; }
      .pgai-sc-reasons { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 9px; }
      .pgai-sc-tag {
        background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.18);
        padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 600;
      }
      .pgai-sc-cta { margin-top: 11px; font-size: 12px; font-weight: 700; color: #fde68a; display: flex; align-items: center; gap: 5px; }
    </style>
    <div class="pgai-sc-head">
      <span class="pgai-sc-ico">&#9888;</span>
      <div>
        <div class="pgai-sc-title">SUSPICIOUS PAGE</div>
        <div class="pgai-sc-sub">PhishGuard AI &middot; caution advised</div>
      </div>
      <span class="pgai-sc-score">${ui.finalRiskScore}/100</span>
    </div>
    <div class="pgai-sc-body">${reasons.length ? reasons.map((r) => '&bull; ' + r).join('<br>') : 'This page shows medium-risk patterns. Verify before entering any personal data.'}</div>
    <div class="pgai-sc-cta">Click for full analysis &rarr;</div>
  `;
  chip.addEventListener('click', () => {
    showAnalysisUI(ui);
    chip.remove();
  });
  document.body.appendChild(chip);
}

// ============================================================================
// PASSWORD-FIELD ALARM (v3.2)
// ============================================================================

let pwAlarmUi: ReturnType<typeof mapScanResult> | null = null;
let pwAlarmInput: HTMLInputElement | null = null;
let pwNotified = false;
let pwRafPending = false;

function armPasswordAlarm(ui: ReturnType<typeof mapScanResult>): void {
  const pred = String(ui?.finalPrediction ?? '').toLowerCase();
  if (pred !== 'phishing' && pred !== 'suspicious') return;
  pwAlarmUi = ui;
  if (isPwDismissed()) return;

  const existingField = document.querySelector('input[type="password"]') as HTMLInputElement | null;
  if (existingField) showPasswordAlarm(existingField);

  document.addEventListener('focusin', onPasswordFocus, true);
  window.addEventListener('scroll', positionPasswordAlarm, { passive: true });
  window.addEventListener('resize', positionPasswordAlarm, { passive: true });
}

function onPasswordFocus(event: FocusEvent): void {
  const el = event.target as HTMLElement | null;
  if (!el || (el as HTMLInputElement).type !== 'password') return;
  showPasswordAlarm(el as HTMLInputElement);
}

function isPwDismissed(): boolean {
  try {
    return sessionStorage.getItem('pgai-pw-dismissed') === '1';
  } catch {
    return false;
  }
}

function dismissPasswordAlarm(): void {
  try {
    sessionStorage.setItem('pgai-pw-dismissed', '1');
  } catch { /* storage may be unavailable */ }
  document.getElementById('pgai-pw-alarm')?.remove();
  pwAlarmInput = null;
}

function showPasswordAlarm(input: HTMLInputElement): void {
  if (isPwDismissed()) return;
  if (!document.documentElement.contains(input)) return;
  pwAlarmInput = input;

  let alarm = document.getElementById('pgai-pw-alarm');
  if (!alarm) {
    alarm = document.createElement('div');
    alarm.id = 'pgai-pw-alarm';
    document.body.appendChild(alarm);
  }

  const danger = String(pwAlarmUi?.finalPrediction ?? '').toLowerCase() === 'phishing';
  alarm.className = danger ? 'danger' : 'warn';
  const pwScore = pwAlarmUi ? Math.round(pwAlarmUi.finalRiskScore) : null;
  alarm.innerHTML = `
    <style>
      #pgai-pw-alarm {
        position: fixed; left: -9999px; top: -9999px; z-index: 2147483647;
        max-width: min(400px, calc(100vw - 24px));
        padding: 16px 18px; border-radius: 14px; color: #fff;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 13.5px; line-height: 1.5;
        box-shadow: 0 14px 38px rgba(0, 0, 0, 0.45);
        animation: pgai-pw-in 0.18s ease;
      }
      @keyframes pgai-pw-in { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
      #pgai-pw-alarm.danger {
        background: linear-gradient(150deg, #7f1d1d, #b91c1c 60%, #dc2626);
        border: 1.5px solid #fca5a5;
        animation: pgai-pw-in .18s ease, pgai-pw-danger-glow 1.6s ease-in-out infinite;
      }
      @keyframes pgai-pw-danger-glow {
        0%, 100% { box-shadow: 0 14px 38px rgba(0,0,0,.45), 0 0 0 0 rgba(239,68,68,.45); }
        50%      { box-shadow: 0 14px 38px rgba(0,0,0,.45), 0 0 26px 5px rgba(239,68,68,.4); }
      }
      #pgai-pw-alarm.warn {
        background: linear-gradient(150deg, #451a03, #92400e 60%, #d97706);
        border: 1.5px solid #fde68a;
      }
      .pgai-pw-row { display: flex; align-items: flex-start; gap: 12px; }
      .pgai-pw-ico {
        width: 40px; height: 40px; flex-shrink: 0; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        background: rgba(255,255,255,.15); border: 2px solid rgba(255,255,255,.55); font-size: 20px;
      }
      .pgai-pw-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
      .pgai-pw-text strong.pgai-pw-title { display: block; font-size: 15.5px; letter-spacing: .03em; margin-bottom: 3px; }
      .pgai-pw-score {
        background: rgba(0,0,0,.35); border: 1px solid rgba(255,255,255,.4);
        padding: 2px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 800; white-space: nowrap;
      }
      .pgai-pw-text .pgai-pw-desc { font-size: 13px; opacity: .95; }
      .pgai-pw-actions { display: flex; gap: 8px; margin-top: 12px; }
      .pgai-pw-btn { padding: 7px 14px; border-radius: 8px; font-size: 12.5px; font-weight: 700; cursor: pointer; border: none; }
      #pgai-pw-details { background: rgba(255, 255, 255, 0.22); color: #fff; }
      #pgai-pw-dismiss { background: #fff; color: #7f1d1d; }
      #pgai-pw-alarm.warn #pgai-pw-dismiss { color: #78350f; }
    </style>
    <div class="pgai-pw-row">
      <span class="pgai-pw-ico">${danger ? '&#9940;' : '&#128274;'}</span>
      <div class="pgai-pw-text">
        <div class="pgai-pw-head">
          <strong class="pgai-pw-title">${danger ? 'DO NOT ENTER YOUR PASSWORD' : 'PASSWORD WARNING'}</strong>
          ${pwScore !== null ? `<span class="pgai-pw-score">RISK ${pwScore}/100</span>` : ''}
        </div>
        <span class="pgai-pw-desc">PhishGuard flagged this page (${escapeHtmlAttr(window.location.hostname)}) as
        <strong>${danger ? 'PHISHING' : 'SUSPICIOUS'}</strong>. Typing here may hand your credentials to attackers.</span>
      </div>
    </div>
    <div class="pgai-pw-actions">
      <button class="pgai-pw-btn" id="pgai-pw-details">View details</button>
      <button class="pgai-pw-btn" id="pgai-pw-pdf">📄 Save PDF report</button>
      <button class="pgai-pw-btn" id="pgai-pw-dismiss">Dismiss</button>
    </div>
  `;

  alarm.querySelector('#pgai-pw-dismiss')!.addEventListener('click', dismissPasswordAlarm);
  alarm.querySelector('#pgai-pw-pdf')!.addEventListener('click', () => {
    if (!pwAlarmUi) return;
    try {
      downloadScanReport(uiToScanResult(pwAlarmUi));
      const btn = alarm.querySelector('#pgai-pw-pdf') as HTMLButtonElement;
      btn.textContent = '✓ Report saved';
      setTimeout(() => { btn.textContent = '📄 Save PDF report'; }, 2200);
    } catch (err) {
      console.error('[PhishGuard] PDF report failed:', err);
    }
  });
  alarm.querySelector('#pgai-pw-details')!.addEventListener('click', () => {
    if (pwAlarmUi) showAnalysisUI(pwAlarmUi);
  });

  notifyPasswordAlarmOnce();
  positionPasswordAlarm();
}

function positionPasswordAlarm(): void {
  const alarm = document.getElementById('pgai-pw-alarm');
  if (!alarm) return;
  if (!pwAlarmInput || !document.documentElement.contains(pwAlarmInput)) {
    pwAlarmInput = null;
    alarm.remove();
    return;
  }
  if (pwRafPending) return;
  pwRafPending = true;
  requestAnimationFrame(() => {
    pwRafPending = false;
    const a = document.getElementById('pgai-pw-alarm');
    if (!a) return;
    if (!pwAlarmInput || !document.documentElement.contains(pwAlarmInput)) {
      pwAlarmInput = null;
      a.remove();
      return;
    }
    const rect = pwAlarmInput.getBoundingClientRect();
    const left = Math.max(12, Math.min(rect.left, window.innerWidth - a.offsetWidth - 12));
    const above = rect.top - a.offsetHeight - 10;
    a.style.left = `${left}px`;
    a.style.top = `${above >= 12 ? above : Math.min(rect.bottom + 10, window.innerHeight - a.offsetHeight - 12)}px`;
  });
}

function notifyPasswordAlarmOnce(): void {
  if (pwNotified) return;
  pwNotified = true;
  try {
    chrome.runtime.sendMessage(
      { action: 'notifyPasswordAlarm', data: { url: window.location.href } },
      () => void chrome.runtime.lastError
    );
  } catch { /* SW asleep or channel race - non-critical */ }
}

function escapeHtmlAttr(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Helper functions
function getBadgeIcon(prediction: string): string {
  switch (prediction) {
    case 'Phishing': return '🔴';
    case 'Suspicious': return '🟠';
    case 'Safe': return '🟢';
    default: return '⚪';
  }
}

function getProgressClass(threatLevel: string): string {
  switch (threatLevel) {
    case 'High': return 'phishing';
    case 'Medium': return 'suspicious';
    case 'Low': return 'safe';
    default: return 'safe';
  }
}

function getProgressOffset(score: number): number {
  const circumference = 2 * Math.PI * 34; // 213.6
  return circumference * (1 - score / 100);
}

function getThreatColor(threatLevel: string): string {
  switch (threatLevel) {
    case 'High': return '#ef4444';
    case 'Medium': return '#f59e0b';
    case 'Low': return '#10b981';
    default: return '#64748b';
  }
}

function getSourcesText(sources: any): string {
  const parts = [];
  if (sources.local) parts.push('Local');
  if (sources.backend) parts.push('Backend ML');
  if (sources.threatIntel) parts.push('Threat Intel');
  return parts.join(' + ') || 'Local';
}

// Auto-protect sweep on page load (Phase E) - includes legacy float-button logic
void runAutoProtect();

// Listen for setting changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.phishguard_settings) {
    const settings = changes.phishguard_settings.newValue;
    const btn = document.getElementById('phishguard-float-btn');
    if (settings.showBadge === false && btn) {
      btn.remove();
    } else if (settings.showBadge !== false && !btn && settings.autoAnalyze !== false) {
      injectPhishGuardButton();
    }
    void runAutoProtect();
  }
});

console.log('[ContentScript] PhishGuard AI content script loaded');
