#!/usr/bin/env bash
# PhishGuard AI - competition demo server.
# Serves the simulated phishing login page from your own laptop so the
# live demo never depends on venue internet or a real malicious site.
#
#   ./serve.sh          -> port 8020
#   ./serve.sh 9000     -> custom port
set -euo pipefail
cd "$(dirname "$0")"
PORT="${1:-8020}"

echo ""
echo "  PhishGuard demo server -> http://localhost:$PORT"
echo ""
echo "  Open this URL in the browser:"
echo "    http://localhost:$PORT/paypal.com-account-security-verify-login-alert/index.html"
echo ""
echo "  Expected: red auto-protect banner + password-field alarm + red badge."
echo "  Press Ctrl+C to stop."
echo ""

exec python3 -m http.server "$PORT"
