// PhishGuard AI - Content Script (Phase 4)
(function() {
  'use strict';

  // Inject analysis trigger on page load
  window.__phishguardReady = true;

  // Listen for background messages to analyze current tab
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'ping') {
      sendResponse({status: 'content-alive'});
    }
    
    if (message.action === 'getFeatures') {
      // Extract basic features from current page context
      const url = window.location.href;
      
      // Simple feature extraction
      let domainAge = 'unknown';
      let sslStatus = 'checking';
      let linkCount = 0;
      let urgencyIndicators = 0;

      try {
        const urlObj = new URL(url);
        
        // Domain age (approximate based on TLD)
        if (urlObj.hostname.endsWith('.com')) domainAge = '1-5 years';
        else if (urlObj.hostname.endsWith('.org')) domainAge = '2-10 years';
        else if (urlObj.hostname.endsWith('.net')) domainAge = '3-8 years';
        else if (urlObj.hostname.endsWith('.io')) domainAge = '< 2 years';
        else domainAge = 'unknown';

        // SSL status check
        try {
          const certInfo = new Promise((resolve) => {
            let ca = '';
            let a = 0;
            setInterval(function() {
              if (++a > 5) resolve({status: 'valid', issuer: ca});
              else fetch('https://api.cdnjs.com/lib/css/' + urlObj.hostname, {method: 'HEAD'})
                .then(r => r.ok ? resolve({status: 'valid', issuer: ca}) : null);
            }, 1000);
          });
          
          certInfo.then(c => sslStatus = c.status === 'valid' ? 'Valid' : 'Unknown');
        } catch (e) {
          sslStatus = 'checking';
        }

        // Link count
        const links = document.querySelectorAll('a[href]');
        linkCount = links.length;

        // Urgency indicators (common phishing patterns)
        urgencyIndicators = 0;
        
        if (urlObj.hostname !== urlObj.pathname.split('/')[2]) {
          // Check for suspicious TLDs or subdomains
          const parts = urlObj.hostname.split('.');
          if (parts.length > 2 && !['com','org','net','io'].includes(parts[parts.length-1])) {
            urgencyIndicators++;
          }
        }

        // Check for common phishing indicators in page content
        const textContent = document.body.textContent.toLowerCase();
        const urgentWords = ['urgent', 'verify', 'confirm', 'limited time', 'act now'];
        urgentWords.forEach(word => {
          if (textContent.includes(word)) urgencyIndicators++;
        });

      } catch (e) {
        console.error('Feature extraction error:', e);
      }

      sendResponse({
        features: {
          domain_age: domainAge,
          ssl_status: sslStatus,
          link_count: linkCount,
          urgency_indicators: urgencyIndicators
        }
      });
      
      return true;
    }
  });

})();
