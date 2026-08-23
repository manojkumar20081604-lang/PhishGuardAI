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
URL_PATH="/paypal.com-account-security-verify-login-alert/index.html"
FANCY_HOST="secure-login.paypal-verify-alert.top"

check() {
  curl -s -o /dev/null "http://localhost:$PORT$URL_PATH" 2>/dev/null
}

# Fancy hostname works only after the /etc/hosts entry exists (see below)
if getent hosts "$FANCY_HOST" >/dev/null 2>&1; then
  PUBLIC_URL="http://$FANCY_HOST:$PORT$URL_PATH"
else
  PUBLIC_URL="http://localhost:$PORT$URL_PATH"
fi

if check; then
  echo ""
  echo "  ✅ Demo server is ALREADY running - nothing to start."
  echo ""
  echo "     Open:  $PUBLIC_URL"
  if ! getent hosts "$FANCY_HOST" >/dev/null 2>&1; then
    echo ""
    echo "  💡 Optional (hides 'localhost' on stage): run ONCE,"
    echo "     then restart this script:"
    echo "       echo '127.0.0.1 $FANCY_HOST' | sudo tee -a /etc/hosts"
  fi
  echo ""
  echo "  (To restart fresh: kill the old one with"
  echo "   fuser -k $PORT/tcp   then run ./serve.sh again)"
  exit 0
fi

echo ""
echo "  PhishGuard demo server -> http://localhost:$PORT"
echo ""
echo "  Open this URL in the browser:"
echo "    $PUBLIC_URL"
if ! getent hosts "$FANCY_HOST" >/dev/null 2>&1; then
  echo ""
  echo "  💡 Optional (hides 'localhost' on stage): run ONCE,"
  echo "     then restart this script:"
  echo "       echo '127.0.0.1 $FANCY_HOST' | sudo tee -a /etc/hosts"
fi
echo ""
echo "  Expected: red auto-protect banner + password-field alarm + red badge."
echo "  Press Ctrl+C to stop."
echo ""

exec python3 -m http.server "$PORT"
