# PhishGuard AI 🛡️

**Offline AI phishing detection for your browser.** PhishGuard scans links and messages
with an ONNX neural network that runs entirely on your device — no data ever leaves
your browser.

- Chrome / Edge / Brave / Opera (Manifest V3) + Firefox
- Fully functional with **zero servers**: the ML model is bundled inside the extension
- Optional Flask backend enrichment if *you* choose to enable it

## Why local-first?

Cloud phishing scanners send every link you touch to a third party. PhishGuard flips
that: the trained model (`url-model-v3.onnx`, ~KBs, WASM inference) ships inside the
extension and answers in milliseconds, offline. Your browsing stays yours.

## Features

| Feature | What it does |
|---|---|
| 🔍 **URL scanner** | Popup analysis with risk score 0–100, verdict + human-readable reasons |
| ✉️📱 **Message scanner** | Paste an email/SMS — detects urgency scams, prize fraud, OTP tricks, spoofed senders; extracted links are run through the URL engine |
| 🛡️ **Auto-Protect** | Silent on-load scanning: red banner + optional full-page block for phishing, amber chip for suspicious pages |
| 🔑 **Password-field alarm** | On a flagged page, any password field triggers an inline warning + desktop notification before you type |
| 🤍🖤 **Trust lists** | Trusted domains are never scanned; blocked domains are always flagged (subdomains included) |
| 🖱️ **Right-click scan** | Scan any link without visiting it |
| ⌨️ **Keyboard shortcut** | `Alt+Shift+S` (macOS `Cmd+Shift+S`) scans the current tab |
| 📊 **Stats dashboard** | 14-day charts, verdict donut, lifetime counters — all stored locally |
| 🧬 **Homoglyph detector** | Catches punycode/look-alike domains (`аpple.com` with a Cyrillic а), invisible characters, brand imitation — FP-safe for real internationalized domains |
| 📄 **PDF reports** | One-click zero-dependency scan report export |
| 💾 **Backup & restore** | Export/import settings + trust lists + stats as one JSON file |
| ⏳ **Model-age indicator** | Shows model training date with freshness warnings (amber at 90 days, red at 180) |

## Install

### From the stores
- Chrome Web Store / Firefox Add-ons (AMO): links pending submission — see
  `store/LISTINGS.md`.

### From source (load unpacked)

```bash
git clone https://github.com/manojkumar/PhishGuardAI.git
cd PhishGuardAI/extension
npm ci
npm run build          # or: npm run build:chrome / build:firefox
```

Then:
- **Chrome**: `chrome://extensions` → enable Developer mode → *Load unpacked* → select `dist/`
- **Firefox**: `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on…* → pick `manifest.json` in `dist-firefox/`

## Architecture

```
Analysis request (popup / auto-protect / right-click / shortcut)
   │
   ▼
1. Trust lists ──── trusted → instant Safe · blocked → instant flag
   │
   ▼
2. Local cache ──── recent result? return instantly (IndexedDB)
   │
   ▼
3. LOCAL engine ─── features.ts (10 URL features)
   │                url-model-v3.onnx (WASM, bundled)
   │                homoglyph inspection · risk fusion · explainer
   ▼
4. OPTIONAL backend enrichment (Flask, user-enabled only)
```

The Flask backend under `backend/` is **optional** — an enrichment server for threat
intel and server-side ML, never a dependency.

## Development

```bash
cd extension
npm run dev          # watch-mode build
npm run verify       # typecheck + eslint + vitest + both browser builds (one command)
npm test             # 28 automated tests incl. golden-vector parity + homoglyph probes
npm run package      # store zips -> ../store/packages/
```

Python side (backend/training):

```bash
pytest backend/tests           # backend parity tests
./refresh-model.sh             # retrain pipeline end-to-end (see RETRAINING.md)
```

## Retraining the model

Phishing churns fast. The extension shows model age in Settings → About; when it turns
amber/red, run [`refresh-model.sh`](refresh-model.sh). Full details, manual steps, and
false-positive guidance live in [RETRAINING.md](RETRAINING.md).

## Privacy

- No telemetry. No analytics. No accounts.
- Scans, trust lists, settings, and stats never leave the browser (local storage only).
- Backend/server mode is off by default; enabling it is explicit and its URL is yours.
- Data-collection declaration: none (see store listings).

## Project layout

```
extension/            MV3 extension source (TypeScript + Vite)
  src/ml/             ONNX engine, features, risk fusion, explainer, text detector
  src/security/       homoglyph/punycode detector
  src/background/     service worker: analysis pipeline, commands, notifications
  src/content/        auto-protect UI, password alarm, banners
  src/options/        settings, trust lists, stats dashboard, backup/restore
  tests/              vitest suites (parity, probes, offline, message scan, …)
backend/              optional Flask enrichment API + training tools
backend/tools/        dataset fetcher + standalone trainer (sklearn → ONNX)
store/                privacy policy, listing pack, packaged zips
docs/ARCHITECTURE.md  deeper architecture notes
```

## Contributing & support

Issues and PRs welcome — please run `npm run verify` before submitting. Found a site
PhishGuard gets wrong? Open an issue with the URL pattern (not live credentials!).

## License

[MIT](LICENSE) © 2026 Manoj Kumar
