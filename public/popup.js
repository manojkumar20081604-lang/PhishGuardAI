// PhishGuard AI - Popup Logic (Phase 4)
document.addEventListener('DOMContentLoaded', () => {
  const analyzeBtn = document.getElementById('analyze-btn');
  const loadingOverlay = document.getElementById('loading-overlay');
  const urlDisplay = document.getElementById('url-display');
  const resultContainer = document.getElementById('result-container');

  // Get current tab URL
  chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
    if (tabs[0]) {
      urlDisplay.textContent = tabs[0].url;
      
      // Auto-analyze on load
      analyzePage(tabs[0].url);
    }
  });

  analyzeBtn.addEventListener('click', () => {
    chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
      if (tabs[0]) {
        analyzePage(tabs[0].url);
      }
    });
  });

  async function analyzePage(url) {
    // Show loading
    loadingOverlay.classList.remove('hidden');
    
    try {
      // Send to background script
      const response = await chrome.runtime.sendMessage({action: 'analyzePage'});
      
      if (response && response.result) {
        displayResult(response.result);
      } else {
        resultContainer.innerHTML = `
          <div class="result-box result-suspicious">
            ⚠️ No analysis data available
          </div>
        `;
      }
    } catch (err) {
      console.error('Analysis error:', err);
      resultContainer.innerHTML = `
        <div class="result-box result-suspicious">
          ⚠️ Analysis failed: ${err.message}
        </div>
      `;
    } finally {
      loadingOverlay.classList.add('hidden');
    }
  }

  function displayResult(result) {
    const score = result.score || 0;
    let statusClass, statusText, icon;

    if (score < 30) {
      statusClass = 'result-safe';
      statusText = 'Likely Safe';
      icon = '✅';
    } else if (score < 70) {
      statusClass = 'result-suspicious';
      statusText = 'Suspicious - Review Carefully';
      icon = '⚠️';
    } else {
      statusClass = 'result-phishing';
      statusText = 'High Risk - Possible Phish!';
      icon = '🔴';
    }

    // Update status dot color
    const statusDot = document.getElementById('status-dot');
    statusDot.style.background = score < 30 ? '#10b981' : (score < 70 ? '#f59e0b' : '#ef4444');

    resultContainer.innerHTML = `
      <div class="result-box ${statusClass}">
        ${icon} ${statusText}<br>
        <small style="font-weight:normal; opacity:0.8;">Risk Score: ${score}/100</small>
        
        <div class="score-meter">
          <div id="score-fill" class="score-fill" style="width: ${Math.min(score, 100)}%"></div>
        </div>

        <ul class="reasons-list">
          ${result.reasons?.map(r => `<li>${r}</li>`).join('') || '<li>No specific reasons</li>'}
        </ul>

        <div class="features-grid">
          <div class="feature-item"><strong>Domain Age:</strong> ${result.features?.domain_age || 'N/A'}</div>
          <div class="feature-item"><strong>SSL Status:</strong> ${result.features?.ssl_status || 'N/A'}</div>
          <div class="feature-item"><strong>Link Count:</strong> ${result.features?.link_count || 0}</div>
          <div class="feature-item"><strong>Urgency:</strong> ${result.features?.urgency_indicators || 0} indicators</div>
        </div>
      </div>
    `;

    // Animate score fill
    setTimeout(() => {
      const fill = document.getElementById('score-fill');
      if (fill) {
        fill.style.width = `${Math.min(score, 100)}%`;
      }
    }, 50);
  }
});
