# PhishGuard AI — Master Plan v3.2
# "Standalone Extension + Feature Pack"

> ## STATUS: ✅ PHASES A–K COMPLETE — v3.2.0 PACKAGED
> - Embedded ONNX brain v3 (brand-safety gate permanent, 58 known-brand domains)
> - Popup/background/context-menu ALL route through local-first pipeline
> - Features live: Trust Lists · Auto-Protect · Right-Click Scan · Stats · Message Scanner
> - 28/28 automated tests · both browser builds green · web-ext lint 0 errors
> - User field-tested: offline scans ✓ · false-positive (YouTube) caught & fixed via retrain
> - Phases J+K shipped: store listing pack + v3.2 feature pack (homoglyph detector,
>   Alt+Shift+S shortcut, password-field alarm, settings export/import, model-age
>   indicator, RETRAINING.md + refresh-model.sh)
>   · v3.1.0 AND v3.2.0 zips in store/packages/ (chrome + firefox, sourcemaps excluded)
>
> Post-mortems locked into tests: golden-vector parity · brand-safety probe gate.
> Remaining (user actions only): host privacy policy · capture screenshots · submit to stores.
>
> SESSION RESUME POINT (updated Aug 23 2026):
> - ✅ v3.2 FEATURE PACK COMPLETE & VERIFIED (npm run verify green end-to-end):
>   - Homoglyph/punycode detector wired into analyzeLocally (escalation + reasons)
>     + no-control-regex lint fix; homoglyph.test.ts green
>   - Alt+Shift+S / Cmd+Shift+S shortcut: manifest commands key survives both builds,
>     onCommand handler notifies verdict (background/index.ts)
>   - Password-field alarm (content script): inline banner anchored above password
>     fields on flagged pages + one desktop notification via new background
>     'notifyPasswordAlarm' message; per-visit dismissal; respects Auto-Protect level
>   - Settings export/import (Options → Backup & Restore): JSON bundle = settings +
>     trust lists + stats; import validates/sanitizes/confirms before replacing
>   - Model-age indicator (Options → About): reads url-model-v3-meta.json trained_at;
>     amber at 90d, red at 180d; version string now from getManifest()
>   - RETRAINING.md runbook + ./refresh-model.sh (fetch → train → sync public/models → tests)
>   - README.md rewritten · CHANGELOG.md created · versions bumped to 3.2.0
>   - Repackaged: store/packages/phishguard-ai-{chrome,firefox}-v3.2.0.zip
> - ✅ ChatGPT FP CONFIRMED FIXED: chatgpt.com URL scans safe through full pipeline (urlProbes.test.ts)
> - ✅ OTP scam regression GREEN (messageScan.test.ts)
> - ✅ Phase I CLOSED: offline test automated in tests/offline.test.ts (Flask dead → local
>   fallback instant, toggle off/on clean); Firefox pass = build + manifest + web-ext lint 0 errors
> - ✅ Phase J CLOSED: see store/LISTINGS.md for the full submission pack
>   - gecko data_collection_permissions: none declared; strict_min_version raised to 140.0
>     (first version supporting that key; matches current ESR baseline)
>   - manifest description rewritten for local-first (old text still said "Flask backend")
>   - packaging: extension/scripts/package.mjs → npm run package / npm run verify
> - Fix shipped: ml/engine.ts isNodeRuntime() no longer keyed on chrome global
> - Post-J fixes from user testing (Aug 23 2026):
>   - Popup readability: Phase H controls were white-on-white; full light theme,
>     body base styles added, missing result/modal/history CSS written
>   - NEW: one-click PDF scan report (utils/reportPdf.ts, zero-dependency PDF 1.4
>     writer; qpdf-clean output; 4 structural tests) - "PDF Report" button in popup
>
> AMO SUBMISSION (Aug 23 2026): 🚀 SUBMITTED - v3.2.1 in review
>   - gecko id: {5ECEB6B6-6AF9-47EB-BD6B-FE77E70C9B96} (example.com id was taken)
>   - privacy policy LIVE: manojkumar20081604-lang.github.io/PhishGuardAI/
>     privacy-policy.html (GitHub Pages, /docs folder)
>   - source package verified reproducible: git archive -> npm ci -> build:firefox
>   - desktop-only for now (popup UX unsupported on Android); v3.3 candidate
> - Next up when resumed: CWS submission (needs $5) OR parked v4 ideas

> Status of previous plan (v3.0 backend migration): ✅ COMPLETE & VERIFIED
> - Pure API client architecture shipped (services/ layer)
> - All backend endpoints live (`/api/v1/*`), smoke-tested 200 OK
> - Build green: tsc clean · eslint clean · vite build passes
>
> This plan supersedes it: the AI brain moves INSIDE the extension.
> Flask backend becomes an optional enrichment server, not a dependency.

═══════════════════════════════════════════════════════════════

## GOALS

| Goal | Decision |
|---|---|
| AI runs inside the extension | ✅ ONNX model bundled, fully offline |
| Browsers | Chrome family (dist/) + Firefox (dist-firefox/) |
| Path | Test locally first → public stores after |
| Version | 3.1.0 |

## ARCHITECTURE SHIFT

```
BEFORE (v3.0)                       AFTER (v3.1)
Browser 🧩 ──► Flask :5000          Browser 🧩
              (required)              ├── url-model.onnx      (bundled)
                                      ├── ml/features.ts      (JS port)
                                      ├── ml/riskEngine.ts    (JS port)
                                      ├── ml/explainer.ts     (JS port)
                                      ├── ml/textDetector.ts  (email/SMS)
                                      └── services/* → Flask  (OPTIONAL toggle)
```

Rule: every analysis path = local engine FIRST, trust-list check BEFORE that,
backend enrichment only if user enabled it.

═══════════════════════════════════════════════════════════════

Phase A: Train & Export the Model (Python)

Directory:
backend/tools/
├── fetch_dataset.py        # OpenPhish feed (phishing) + Tranco top-10k (legit)
└── train_standalone.py     # sklearn pipeline → ONNX

Steps:
- Use the EXACT same 10 features as live API (url_length, has_https,
  has_at_symbol, has_ip_address, dash_count, digit_ratio,
  special_char_count, subdirectory_count, suspicious_tld, entropy)
- Start with LogisticRegression (hard to overfit); try GradientBoosting, keep winner
- Export via skl2onnx → extension/src/assets/url-model-v1.onnx  (<5MB target)
- PARITY TEST (non-negotiable):
  backend/tests/test_parity.py
  500 golden URLs → Flask ml_service vs onnxruntime-web must agree

Verification: pytest backend/tests → green, precision/recall report printed.


Phase B: Embed the Brain (TypeScript)

New module (additive — touches nothing else):

extension/src/ml/
├── features.ts       # port of extract_url_features (pure string math)
├── engine.ts         # onnxruntime-web loader → predict(url) → {prediction, confidence}
├── riskEngine.ts     # port of risk_engine.py fusion (ML score + heuristics blend)
└── explainer.ts      # port of explainer.py reason generation

Wiring:
- background/index.ts analyze flow:
    checkTrust(url)            ← Phase D (trust lists) lands before this matters
    → cache.get(url)           ← reuse db/cache.ts
    → engine.predict(url)      ← LOCAL, ~ms fast
    → riskEngine.fuse() → ScanResult (same shape as today!)
- services/*.ts stay untouched → become OPTIONAL backend enrichment
- manifest CSP addition (both browsers need this to run WASM):
    "content_security_policy": {
      "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
    }
- popup UI: ZERO changes (result shape identical by design)


Phase C: One Source → Two Browser Builds

Build outputs:
- npm run build:chrome   → dist/          (Chrome, Edge, Brave, Opera)
- npm run build:firefox  → dist-firefox/

Manifest factory script (scripts/make-manifests.mjs):
- ONE template manifest.json → two generated variants
- Firefox variant adds:
    "background": { "service_worker": "background.js",
                    "scripts": ["background.js"] },   # event page fallback
    "browser_specific_settings": {
      "gecko": { "id": "phishguard@example.com", "strict_min_version": "113.0" }
    }

Verification: verify.sh = tsc --noEmit + both builds + parity test


Phase D: Feature — Trust Lists 🤍🖤  (BUILD FIRST, others depend on it)

extension/src/trust/lists.ts
- Storage (chrome.storage.local): { trusted: string[], blocked: string[] }
- checkTrust(url): 'trusted' | 'blocked' | unlisted
- Background hook: checked BEFORE cache/engine on every path

options/options.js additions:
- Trust Lists manager UI (add/remove domain, shows count)

Behavior:
- trusted  → never analyzed, always green badge
- blocked  → instant red verdict regardless of AI score


Phase E: Feature — Auto-Protect 🛡️  (content script is already 60% there)

Existing assets reused: showWarningBanner(), phishguard_settings flags,
db/cache.ts result reuse (no repeat analysis cost).

Flow on page load:
  if trusted → skip
  cached/local predict (silent)
  ├─ phishing   → red banner + optional full-screen block page ("Go back")
  ├─ suspicious → amber corner badge only
  └─ safe       → nothing visible

New setting in options:
  Auto-protect level: Off / Suspicious+ / All threats   (default: Suspicious+)

Toolbar badge per tab: chrome.action.setBadgeText/Color (green/amber/red).


Phase F: Feature — Right-Click Scan 🖱️

manifest permissions ADD: "contextMenus", "notifications"

background/index.ts:
  chrome.contextMenus.create({
    id: 'pg-scan-link',
    title: '🛡️ Scan this link with PhishGuard',
    contexts: ['link']
  });
  onClicked → analyze(info.linkUrl) → chrome.notifications.create(verdict)
  notification click → focus/open popup flow with result pre-loaded

Works WITHOUT visiting the link (safe for sketchy URLs).


Phase G: Feature — Stats Dashboard 📊

Data source: db/cache.ts already stores every scan (url, prediction, score, ts).

popup footer strip:
  "🛡️ N threats blocked this week"

options page → new Stats tab:
- inline SVG charts ONLY (no chart library)
- scans per day (14d bars), risk-level breakdown donut, all-time counters
- reset-stats button


Phase H: Feature — Email / SMS Scanner ✉️📱  (biggest, built last)

popup gets second tab: [ URL Scan | Message Scan ]
- textarea paste → detect type (email/SMS) → local analysis → verdict card

extension/src/ml/textDetector.ts:
- TS port of legacy email_detector.py + sms_detector.py rules:
  urgency phrases, prize/verify patterns, spoofed sender formats,
  shortened links (→ run URL engine on extracted links!), OTP scams
- OFFLINE like everything else
- Stretch goal (optional): second small ONNX text model

Backend /analyze/email remains available when server mode enabled.


Phase I: Local Testing Round ⭐ (user-driven)

Checklist (both Chrome AND Firefox):
[ ] Load unpacked (chrome://extensions) / temporary add-on (about:debugging)
[ ] Popup scan works offline — Flask KILLED, everything still functions
[ ] Auto-protect banner fires on known-bad test URL, silent on trusted
[ ] Trust lists: trusted skips, blocked flags instantly
[ ] Right-click menu scans a link without visiting it
[ ] Message scan: paste sample phishing email → correct verdict + reasons
[ ] Stats increment correctly; dashboard renders
[ ] Server toggle off/on switches cleanly (no errors either way)
Fix issues as found → re-run verify.sh


Phase J: Store Prep ✅ COMPLETE (Aug 23 2026)

- [x] Privacy policy page — store/privacy-policy.html (host it, paste URL into listings)
- [x] Store listing pack — store/LISTINGS.md (descriptions, single purpose,
      permission justifications, data-disclosure answers, screenshot checklist)
      (screenshots themselves = user captures; CWS $5 once; AMO free; Edge optional)
- [x] web-ext lint for AMO compliance — 0 errors; MISSING_DATA_COLLECTION_PERMISSIONS
      cleared via gecko data_collection_permissions: ["none"] (min version raised to 140.0)
- [x] Zip packaging — extension/scripts/package.mjs → npm run package
      store/packages/phishguard-ai-{chrome,firefox}-v3.1.0.zip (maps excluded)
- [x] npm run verify = typecheck + lint + tests + both builds (one command)


Phase K: v3.2 Feature Pack ✅ COMPLETE (Aug 23 2026)

- [x] Homoglyph/punycode detector — src/security/homoglyph.ts (RFC 3492 decoder,
      confusable folding, invisible-char + brand-imitation escalation, FP-safe for
      pure IDNs); wired into analyzeLocally; tests/homoglyph.test.ts green;
      no-control-regex lint error fixed
- [x] Keyboard shortcut Alt+Shift+S (Cmd+Shift+S on macOS) — manifest commands key +
      onCommand handler in background → verdict notification; verified in both builds
- [x] Password-field alarm — content script arms on flagged pages: inline banner
      anchored above password fields (+ focusin listener for dynamic forms),
      repositions on scroll/resize, per-visit dismissal via sessionStorage;
      background 'notifyPasswordAlarm' message → desktop notification with
      click-through to the tab
- [x] Settings export/import — Options → Backup & Restore: JSON bundle
      {settings, trustLists, stats}; import validates kind/app, sanitizes domains
      via normalizeDomain, confirms before replacing, refreshes all panels
- [x] Model-age indicator — Options → About reads models/url-model-v3-meta.json:
      name · algorithm · trained date · age in days; amber ≥90d ("consider
      retraining"), red ≥180d ("STALE"); version string from getManifest()
- [x] RETRAINING.md runbook + refresh-model.sh one-command pipeline
      (fetch_dataset → train_standalone → sync ONNX+meta into public/models → npm test)
- [x] README.md rewritten (features, architecture diagram, install, dev guide)
      · CHANGELOG.md created (Keep-a-Changelog, 3.2.0/3.1.0/earlier)
- [x] Versions bumped 3.1.0 → 3.2.0 (manifest + package.json); npm run verify green
      (typecheck · eslint 0 errors · 28/28 tests · both builds); repackaged
      store/packages/phishguard-ai-{chrome,firefox}-v3.2.0.zip

═══════════════════════════════════════════════════════════════

TIMELINE

| Order | Work                        | Time |
|-------|-----------------------------|------|
| 1     | Phase A (train/export)      | 1d   |
| 2     | Phase B (embed brain)       | 2d   |
| 3     | Phase C (dual builds)       | 0.5d |
| 4     | Phase D (trust lists)       | 0.5d |
| 5     | Phase E (auto-protect)      | 1d   |
| 6     | Phase F (right-click)       | 0.5d |
| 7     | Phase G (stats dashboard)   | 1d   |
| 8     | Phase H (message scanner)   | 1.5d |
| 9     | Phase I (user testing)      | ~1d  |
| 10    | Phase J (stores)            | later|
| 11    | Phase K (v3.2 feature pack) | 0.5d |

Total ≈ 9.5 days · Version target 3.2.0 (shipped)

RISKS & MITIGATIONS
- ONNX/WASM under MV3 CSP → solved by 'wasm-unsafe-eval' line; tested EARLY in Phase B
- JS features ≠ Python features drift → golden-vector parity tests (Phase A/B)
- Dataset quality → LogisticRegression start; honest precision/recall reporting
- SW termination mid-inference → inference is ms-fast; IDB ops within event lifetime

PARKED (future v4 ideas, designs saved)
- Collective Immune System (page-DNA sensor network)
- Brand-spoofing vision (screenshot pHash matching)
- Deception sandbox / honeypots
- Safari port (needs macOS + $99/yr Apple account)
