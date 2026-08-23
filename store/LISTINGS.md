# PhishGuard AI v3.1.0 — Store Submission Pack

Everything needed to submit to Chrome Web Store and Firefox Add-ons (AMO).
Copy-paste ready. Screenshots are the only thing you must capture by hand.

---

## 0. Packages

| Store | File | Built with |
|---|---|---|
| Chrome Web Store | `store/packages/phishguard-ai-chrome-v3.1.0.zip` | `npm run build:chrome` |
| Firefox AMO | `store/packages/phishguard-ai-firefox-v3.1.0.zip` | `npm run build:firefox` |

Regenerate anytime from `extension/`: `npm run package`

---

## 1. Identity / listing basics (both stores)

- **Name:** PhishGuard AI
- **Version:** 3.1.0
- **Support email:** *(your dev contact — fill before submit)*
- **Support site:** *(repo URL — fill before submit)*
- **Privacy policy URL:** host `store/privacy-policy.html` (GitHub Pages works) and paste the URL.
  Required by CWS because the listing declares broad host permissions; AMO wants it too.

## 2. Single purpose description (CWS required field)

> PhishGuard AI detects phishing links and scam messages. It analyzes URLs and
> pasted text locally on-device and warns the user before dangerous sites open.

## 3. Short description

**CWS (≤132 chars):**
> Offline AI phishing detector. Scans links & messages on-device — no data leaves your browser.

**AMO summary (≤250 chars):**
> Phishing detection that runs entirely inside your browser. On-device AI scans links and messages, with trust lists, auto-protect banners, right-click scanning and stats. No accounts, no telemetry, no data collection.

## 4. Long description

> 🛡️ PhishGuard AI — phishing protection that keeps your data on your device.
>
> Most anti-phishing tools send every link you touch to someone else's server. PhishGuard flips that: a trained AI model is bundled INSIDE the extension, so every scan runs locally. Fast, private, and fully functional offline.
>
> WHAT IT DOES
> • 🔗 URL Scanner — popup verdict (Safe / Suspicious / Phishing) with risk score and plain-language reasons
> • ✉️📱 Message Scanner — paste any email or SMS; catches OTP scams, urgency bait, prize fraud and spoofed senders
> • 🛡️ Auto-Protect — red warning banner on flagged pages, amber badge on suspicious ones, silent when safe
> • 🖱️ Right-Click Scan — check any link without visiting it
> • 🤍🖤 Trust Lists — your own always-safe and always-blocked domains
> • 📊 Stats Dashboard — scans per day, threat breakdown, weekly block count
>
> WHY IT'S PRIVATE BY DESIGN
> • The AI model ships inside the extension — analysis never leaves your machine
> • No account, no analytics, no trackers, no remote scripts
> • Works with Wi-Fi off / Flask stopped — everything is local-first
> • Optional power-user mode can forward scans to a backend YOU host (off by default)
>
> HOW TO USE
> 1. Install — no signup, nothing to configure
> 2. Browse normally — threats are flagged automatically
> 3. Right-click any link to pre-scan it safely
>
> Full privacy policy: see the developer privacy policy link.

## 5. Category & tags

| Field | CWS | AMO |
|---|---|---|
| Category | Productivity | Privacy & Security |
| Tags/keywords | phishing, security, scam detector, url scanner, safety | phishing, security, scam, privacy |

## 6. Data disclosure answers (must match reality — it does)

**CWS "Data usage":** Does your item collect or use user data?
→ **No** ("Collection" per CWS = transmission off device; all processing is local).
Justification text if prompted:

> All analysis is performed on-device by an embedded model. Trust lists,
> preferences and stats are stored only in local extension storage and are
> removed when the extension is uninstalled. No data is transmitted to any
> server operated by the developer. An optional user-configured server mode
> exists but is disabled by default.

**AMO:** manifest declares `data_collection_permissions: { required: ["none"] }` —
answer "No" to the data-collection questions in the dev hub to match.

### Permission justifications (CWS form, paste per permission)

| Permission | Justification |
|---|---|
| activeTab + scripting + `<all_urls>` host access | Required to read the current tab's URL for local phishing analysis and to display warning banners on flagged pages. Page content is evaluated locally and never uploaded. |
| storage | Stores user preferences, trusted/blocked domain lists, cached results and aggregate stats locally on the user's device. |
| contextMenus | Adds the right-click "Scan this link with PhishGuard" entry so users can check links safely before visiting them. |
| notifications | Shows the result of right-click link scans as a desktop notification. |

## 7. Screenshots checklist (capture at 1280×800)

- [ ] Popup — URL Scan tab showing a **Phishing** verdict with reasons (use a test URL like `http://013224.icefactory.cl/`)
- [ ] Popup — Message Scan tab with a pasted OTP scam SMS and its verdict
- [ ] Popup — Safe verdict on chatgpt.com (nice post-fix flex)
- [ ] Options — Stats dashboard (bars + donut visible)
- [ ] Options — Trust Lists manager
- [ ] Right-click context menu open on a link ("🛡️ Scan this link…")
- [ ] Auto-Protect warning banner on a flagged test page

Tip: `chrome://extensions` → load `dist/`, then use OS screenshot tool cropped to 1280×800. AMO accepts the same images.

## 8. Known lint warnings (all benign — do not chase)

- `BACKGROUND_SERVICE_WORKER_IGNORED` — intentional; Firefox uses the event-page fallback we ship.
- `KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION` — `data_collection_permissions` not yet on Fenix; desktop submission unaffected.
- `UNSAFE_VAR_ASSIGNMENT` ×12 — innerHTML with internally-generated strings; no remote content is ever injected.

## 9. Submission order (suggested)

1. Host `privacy-policy.html` → get public URL
2. Fill support email/repo URLs above
3. Capture screenshots
4. AMO first (free, human review, fastest feedback) → then CWS ($5 one-time) → Edge optional later
