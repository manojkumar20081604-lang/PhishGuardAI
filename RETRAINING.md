# PhishGuard AI — Model Retraining Runbook

The extension's detection brain is a bundled ONNX model (`url-model-v3`). Phishing URL
patterns churn constantly — a model that is months old starts missing new kits. This
runbook explains when and how to retrain it.

---

## When to retrain

Check **Settings → About PhishGuard AI → Detection model** inside the extension:

| Indicator | Meaning | Action |
|---|---|---|
| 🟢 green dot, "fresh" | Trained < 90 days ago | Nothing |
| 🟠 amber dot, "consider retraining" | 90–179 days old | Schedule a retrain |
| 🔴 red dot, "STALE" | ≥ 180 days old | Retrain now |

Also retrain sooner if you notice:
- A cluster of real phishing pages scoring as **safe** (missed detections)
- A wave of user reports about the same false positive pattern

## Prerequisites

- Python virtualenv at `.venv/` (repo root) with:
  `scikit-learn`, `skl2onnx`, `onnx`, `onnxruntime`, `numpy`
- Node dependencies installed for the extension (`cd extension && npm ci`)
- Internet access for dataset downloads (OpenPhish + Majestic)

If `.venv` is missing:

```bash
python3 -m venv .venv
.venv/bin/pip install scikit-learn skl2onnx onnx onnxruntime numpy
```

## One-command refresh

From the repository root:

```bash
./refresh-model.sh
```

This chains every step below: fetch datasets → train & compare classifiers → export
ONNX → sync into the extension's runtime folder → run the full extension test suite
(golden-vector parity included). Exit code 0 = safe to ship.

## What the pipeline does

```
backend/tools/fetch_dataset.py
  ├─ OpenPhish community feed        → phishing URLs
  └─ Majestic Million top domains    → legitimate URLs
  └─ writes backend/data/raw/{phishing_urls.txt, legit_urls.txt}

backend/tools/train_standalone.py
  ├─ Extracts the EXACT 10 features the live engine uses (single source of truth:
  │   services/ml_service.py)
  ├─ Compares LogisticRegression vs GradientBoosting, keeps the winner
  ├─ Exports sklearn pipeline → ONNX
  └─ Writes metadata + golden evaluation vectors
```

### Output files

| File | Purpose |
|---|---|
| `extension/src/assets/url-model-v3.onnx` | Bundled source copy of the model |
| `extension/src/assets/url-model-v3-meta.json` | Metadata copy (features, thresholds, metrics) |
| `backend/data/models/url-model-v3-meta.json` | Canonical training metadata |
| `backend/tests/data/golden_urls.json` | Held-out URLs used by the parity tests |
| `extension/public/models/url-model-v3.onnx` | **Runtime model actually loaded by the extension** |
| `extension/public/models/url-model-v3-meta.json` | Runtime metadata (drives the model-age display) |

`refresh-model.sh` performs the final sync into `public/models/`; if you train manually,
copy both files there yourself or the extension will keep running the old model.

## Verifying after a retrain

```bash
cd extension
npm run verify      # typecheck + lint + tests + both browser builds
npm test            # includes backend/tests/data/golden_urls.json parity checks
```

Then manually smoke-test in the browser (chrome://extensions → reload unpacked):
1. Popup-scan a known-good site (github.com) → Safe
2. Popup-scan a URL from the latest OpenPhish feed → Phishing/Suspicious
3. Check Settings → About → Detection model shows today's date, green dot

## False positives vs. retraining

Most false positives should NOT trigger a retrain:

- **Legitimate site flagged** → add it to Trust Lists (Settings → Trust Lists) or to
  `extension/src/trust/knownBrands.ts` if it affects many users, then rebuild.
- **Look-alike domain missed** → check it isn't caught by the homoglyph detector first;
  only retrain if the ML verdict itself was wrong.
- Real feature drift (new TLD abuse patterns etc.) → full retrain via this runbook.

## Versioning convention

Keep the filename `url-model-v3.onnx` for data refreshes — the runtime path and meta
name stay stable, so no extension code changes are needed. Only create a `-v4` when the
feature set or algorithm changes, and update `engine.ts` (`MODEL_FILE`) plus all meta
copies together.
