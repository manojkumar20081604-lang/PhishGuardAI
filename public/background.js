// PhishGuard AI - Background Service Worker (Phase 4)
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard AI v4.0 installed');
});

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzePage') {
    // Extract URL and basic page info
    const url = new URL(sender.tab.url);
    
    // Send to backend for analysis
    fetch('http://localhost:5000/api/analyze/url', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: sender.tab.url})
    })
    .then(res => res.json())
    .then(result => sendResponse(result))
    .catch(err => console.error('Analysis error:', err));
    
    return true; // Keep channel open for async response
  }
  
  if (message.action === 'getFeatures') {
    // Return cached or computed features
    const features = {
      domain_age: 'unknown',
      ssl_status: 'checking',
      link_count: 0,
      urgency_indicators: 0
    };
    sendResponse({features});
    return true;
  }
  
  if (message.action === 'refresh') {
    console.log('Extension refresh requested');
    sendResponse({status: 'refreshed'});
  }
});

// Periodic health check
setInterval(() => {
  chrome.runtime.sendMessage({action: 'ping'}, () => {});
}, 60000); // Ping every minute

chrome.runtime.onMessage.addListener((msg, sender, sendResp) => {
  if (msg.action === 'ping') {
    sendResp({status: 'alive'});
  }
});
