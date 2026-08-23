# 🏆 PhishGuard AI — Competition Stage Kit

Everything needed to win the live demo on the 28th. Rehearse this exact script.

---

## ⚙️ Setup checklist (do this BEFORE leaving home + again at venue)

- [ ] `cd extension && npm run verify` → must print **39/39 tests**, 0 errors
- [ ] Chrome loaded with unpacked extension from `extension/dist/` (**Reload ⟳ it**)
- [ ] Run demo once at home: popup → **▶ Run Demo** → all 4 acts correct
- [ ] Test fake page: `cd demo && ./serve.sh` → open the printed URL → red banner appears
- [ ] Laptop: full battery, screen brightness 100%, close all other tabs
- [ ] Backup on USB: screen recording of both demos + this repo
- [ ] Slides ready with `docs/architecture.svg`

At venue (5 min before): start `./serve.sh`, keep terminal visible but minimized,
open a clean tab. Do NOT rely on venue WiFi — nothing in the demo needs internet.

---

## 🎤 The 4-minute script

**[0:00 — Hook]**
> "Every 11 seconds, someone falls for a phishing site. Antivirus is reactive;
> cloud filters read your browsing to protect you. We built the opposite:
> an AI that lives INSIDE your browser, judges every link locally, and never
> sends your data anywhere."

**[0:30 — Architecture, one slide]**
> "The ONNX model — trained on real phishing feeds — is bundled inside the
> extension. URL features, homoglyph detection, risk fusion: all offline,
> millisecond-fast. The Flask server exists but is optional enrichment."
→ show `docs/architecture.svg`

**[1:00 — Demo Act 1 & 2]**
Open popup → click **▶ Run Demo**.
> "One button runs our attack suite through the real engine. First, a
> baseline: Google stays green — no false alarms. Now the clever attack:
> this domain LOOKS like apple.com — every single letter. It's actually
> Cyrillic characters. Watch… [verdict appears] …flagged, and the report
> explains exactly which trick was used."

**[2:15 — Demo Acts 3 & 4]**
> "A live credential-harvesting kit from a phishing feed — flagged before we'd
> ever visit it. And scams don't only arrive by link — [SMS verdict shows] —
> urgency, fake OTP, shortened link: caught, fully offline."

**[3:00 — The killer moment: your own fake page]**
Switch to tab with the localhost PayPal page.
> "This login page is hosted on THIS laptop right now — I made it. To a human
> it's indistinguishable from PayPal. Reload…" → red auto-protect banner +
> password-field alarm fire.
> "It even warns before you type your password into a flagged page."

**[3:40 — Close]**
> "39 automated tests, dual-browser builds, store-ready packaging. Privacy
> isn't a feature we added — it's the architecture itself. PhishGuard AI."

---

## 👨‍⚖️ Judge Q&A cheat sheet

| Question | Answer |
|---|---|
| "What if a brand-new phishing site appears?" | "Model generalizes on URL anatomy — structure beats novelty. Plus heuristics layer catches what ML misses; unknown-host + credential-form patterns escalate." |
| "Accuracy?" | "F1 ≈ 0.88 on strictly real-world URLs (no augmentation inflation). Precision 0.85 / recall 0.92. Golden-vector parity tests lock Python↔JS behavior." |
| "How is this different from Google Safe Browsing?" | "GSB = cloud lookup, needs connectivity, shares URL history with Google. Ours = zero network, zero telemetry, works on airplane mode." |
| "Can't phishers bypass string analysis?" | "Yes — that's roadmap item #1: screenshot pHash matching of page visuals. Also collective immune system across users." |
| "Is the model big?" | "~KBs-scale ONNX, loads once per browser session, inference in milliseconds even on old laptops." |
| "Why a browser extension and not an app?" | "Phishing happens IN the browser — protect users at the point of attack, with no OS permissions." |

## 🛡️ Failure modes & fallbacks

| Risk | Fallback |
|---|---|
| Popup closes mid-demo (focus loss) | Use "↗ Open in a full tab" version instead |
| Venue laptop lacks Python | Fake-page act → skip live page; replay screen recording |
| Model slow first scan | Pre-warm by running demo once before judges enter |
| Judge asks for random URL test | Offer Message Scan paste instead — deterministic outcomes |
