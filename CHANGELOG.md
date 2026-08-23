# Changelog

All notable changes to PhishGuard AI are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/).

## [3.2.1] — 2026-08-23

### Fixed
- **Free-hosting reputation bug**: `netlify.app` / `vercel.app` removed from the
  known-brand list — their subdomains are user-controlled and a major phishing
  abuse vector. Real-world catch: golden-vector phish on netlify.app was scored
  SAFE (2/100) by the brand gate.
- **Cache fidelity**: scan cache now persists reasons, security tips, confidence,
  risk level and recommendation; PDF reports no longer show empty sections.
- **Stale verdicts**: cache entries carry the model version — anything analyzed
  by an older model auto-invalidates and re-analyzes (fixes pre-retrain
  false positives resurfacing from IndexedDB).
- **Homoglyph table**: added Cyrillic palochka (U+04CF) + 13 more confusables;
  full-punycode brand clones (`www.xn--80ak6aa92e.com` → аррӏе.com) now detected.
- **Brand coverage**: real country-TLD variants added (amazon.in/.co.uk/.de/.ca/.ae,
  google.co.in/.co.uk/.de) plus popular Indian services; explainer copy no longer
  says "Found 0 indicators. Do not enter credentials".
- **PDF report**: version string now read live from the manifest.

### Added
- **Demo mode** in the popup: one-click scripted attack sequence (safe baseline →
  homoglyph clone → hosted phishing kit → OTP SMS) rendered through the real
  pipeline with progress dots; built for presentations.
- Competition demo kit: self-hosted credential-harvesting simulation page
  (`demo/serve.sh`) for offline stage demos; 8 new regression tests guarding
  every demo scenario (39 total).

## [3.2.0] — 2026-08-23

### Added
- **Homoglyph / punycode detector** (`src/security/homoglyph.ts`): catches mixed-script
  look-alike domains, decodes punycode labels (RFC 3492), flags invisible/bidi
  characters and known-brand imitation. FP-safe: genuine internationalized domains are
  never flagged. Wired into the local analysis pipeline with escalation rules; covered
  by `tests/homoglyph.test.ts`.
- **Keyboard shortcut** `Alt+Shift+S` (`Cmd+Shift+S` on macOS) scans the current tab
  from anywhere and reports via desktop notification.
- **Password-field alarm**: when Auto-Protect flags a page as phishing/suspicious and
  the page contains password fields, an inline warning anchors above the field and a
  one-time desktop notification fires. Dismissible per visit; respects the Auto-Protect
  level.
- **Settings export/import** in Options → Backup & Restore: one JSON bundle with
  Auto-Protect settings, trust lists, and statistics. Import validates, sanitizes
  domains, and requires confirmation before replacing.
- **Model-age indicator** in Options → About: reads bundled model metadata and shows
  training date/age with freshness coloring (green <90d, amber <180d, red = stale).
- **Retrain runbook** ([RETRAINING.md]) + `./refresh-model.sh` one-command pipeline:
  fetch datasets → train → export ONNX → sync runtime copies → extension test suite.

### Fixed
- Lint error (`no-control-regex`) in homoglyph non-ASCII check.

## [3.1.0] — 2026-08-23

### Added
- Local-first architecture: bundled ONNX model (`url-model-v3`, GradientBoosting)
  with JS feature parity port — full offline operation, Flask backend now optional.
- Trust Lists (trusted/blocked, subdomain-aware) checked before every analysis path.
- Auto-Protect: silent on-load scanning, red phishing banner, full-screen block page
  for risk ≥ 85, amber chip for suspicious pages, toolbar badge colors per tab.
- Right-click scan for links and pages with verdict notifications and click-through
  to a pre-scanned popup.
- Stats dashboard: popup threat counter plus Options charts (14-day bars, donut,
  lifetime counters, reset).
- Email/SMS message scanner with local rule port (urgency, prize, OTP scams,
  spoofed senders) and link extraction into the URL engine.
- Dual browser builds from one source (`build:chrome` / `build:firefox`) with
  manifest factory and Firefox event-page fallback.
- Store prep: privacy policy, listing pack, AMO data-collection declaration,
  web-ext lint clean, zip packaging script (`npm run package`).
- PDF scan report export (zero-dependency PDF writer).
- Popup light-theme readability overhaul.

### Fixed
- ChatGPT.com false positive (brand-safety gate, locked in by regression tests).
- OTP scam regression covered by tests.
- `isNodeRuntime()` no longer keyed on the Chrome global (Node test compatibility).

## [3.0.x] — 2026-08

- Pure API-client architecture with services layer; all backend endpoints migrated to
  `/api/v1/*`.

## [2.x] — 2026-07/08

- Enterprise upgrade: multi-model ML service, risk engine, explainable AI, self-learning
  feedback loop, threat-intel caching, sandbox analysis, Docker deployment, modern UI,
  permanent scan history, quiz/chatbot endpoints, PDF certificate/report generation.

[3.2.0]: https://github.com/manojkumar/PhishGuardAI/releases/tag/v3.2.0
[3.1.0]: https://github.com/manojkumar/PhishGuardAI/releases/tag/v3.1.0
