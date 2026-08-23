# PhishGuard AI - Browser Extension (Phase 4)

## Files Created

### `public/manifest.json`
Manifest V3 configuration with permissions, host rules, and popup definition.

### `public/background.js`
Service worker that:
- Listens for analysis requests from content scripts
- Communicates with Flask backend via `/api/analyze/url`
- Handles periodic health checks

### `public/popup.html`
Popup UI showing:
- Current URL being analyzed
- Risk score (0-100) with visual meter
- Status indicator (safe/suspicious/phishing)
- Feature breakdown (domain age, SSL status, link count, urgency indicators)
- Detailed reasons for the risk assessment

### `public/popup.js`
Popup logic that:
- Auto-analyzes current tab on load
- Displays results with animated score meter
- Updates status indicator color based on risk level

### `public/content.js`
Content script that:
- Injects analysis trigger into pages
- Extracts basic features (domain age, SSL status, link count)
- Detects urgency indicators in page content
- Communicates with background service worker

### `public/styles.css`
Styling for popup with:
- Dark gradient theme matching backend
- Animated pulse effect on status indicator
- Responsive grid layout for feature display
- Smooth transitions and hover effects

## How It Works

1. **Install**: Load unpacked extension in Chrome/Edge/Firefox
2. **Open**: Navigate to any website
3. **Analyze**: Click "🔍 Analyze This Page" (or auto-analyzes on load)
4. **Review**: See risk score, features, and detailed reasons

## Backend Integration

The extension calls your Flask backend at `http://localhost:5000/api/analyze/url` with the current tab's URL. The backend performs ML-enhanced heuristic scoring and returns a result object that the popup displays.

## Next Steps (Phase 6 - Optional)

Once you're happy with Phase 4, we can add:
- **Threat Intel Service**: VirusTotal/PhishTank API integration
- **Risk Engine Service**: Advanced scoring calculations  
- **Explainer Service**: Explainable AI reasoning
- **Learning Service**: Self-improvement from scan history

## Testing

1. Start Flask backend: `python app.py`
2. Load extension in browser (chrome://extensions/ → "Load unpacked")
3. Select the `public/` folder
4. Navigate to test sites and click analyze
