#!/usr/bin/env bash
# PhishGuard AI - one-command model refresh (see RETRAINING.md)
#
#   ./refresh-model.sh            fetch datasets -> train -> export ONNX ->
#                                 sync runtime copies -> extension test suite
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON="$ROOT/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  echo "✗ .venv/bin/python not found - create it first:"
  echo "    python3 -m venv .venv && .venv/bin/pip install scikit-learn skl2onnx onnx onnxruntime numpy"
  exit 1
fi

echo "==> [1/4] Fetching datasets (OpenPhish + Majestic)"
"$PYTHON" backend/tools/fetch_dataset.py

echo "==> [2/4] Training + exporting ONNX"
"$PYTHON" backend/tools/train_standalone.py

echo "==> [3/4] Syncing model into extension runtime folder"
cp "$ROOT/extension/src/assets/url-model-v3.onnx"      "$ROOT/extension/public/models/url-model-v3.onnx"
cp "$ROOT/extension/src/assets/url-model-v3-meta.json" "$ROOT/extension/public/models/url-model-v3-meta.json"
echo "    synced -> extension/public/models/"

echo "==> [4/4] Running extension test suite"
(cd "$ROOT/extension" && npm test)

echo ""
echo "✓ Model refresh complete. Run: cd extension && npm run package"
