#!/usr/bin/env bash
# PhishGuard AI - competition demo server.
# Serves the simulated phishing login page from your own laptop so the
# live demo never depends on venue internet or a real malicious site.
#
#   sudo ./serve.sh         -> clean URL on port 80 (recommended, needs sudo)
#   ./serve.sh 8020         -> fallback without sudo (port shows in URL)
set -euo pipefail
cd "$(dirname "$0")"

FANCY_HOST="secure-login.paypal-verify-alert.top"
URL_PATH="/signin"
PORT="${1:-80}"

if [ "$PORT" = "80" ] && [ "$(id -u)" != "0" ]; then
  echo ""
  echo "  ⚠️  Port 80 (the invisible, normal-looking port) needs root."
  echo ""
  echo "     Run:   sudo ./serve.sh"
  echo "     ...or use a dev port:  ./serve.sh 8020"
  exit 1
fi

check() {
  curl -s -o /dev/null "http://localhost:$PORT$URL_PATH" 2>/dev/null
}

# Fancy hostname works only after the /etc/hosts entry exists:
#   echo '127.0.0.1 secure-login.paypal-verify-alert.top' | sudo tee -a /etc/hosts
if getent hosts "$FANCY_HOST" >/dev/null 2>&1; then
  HOSTPART="$FANCY_HOST"
else
  HOSTPART="localhost"
fi
[ "$PORT" = "80" ] && PORT_SUFFIX="" || PORT_SUFFIX=":$PORT"
PUBLIC_URL="http://$HOSTPART$PORT_SUFFIX$URL_PATH"

if check; then
  echo ""
  echo "  ✅ Demo server is ALREADY running - nothing to start."
  echo ""
  echo "     Open:  $PUBLIC_URL"
  getent hosts "$FANCY_HOST" >/dev/null 2>&1 || {
    echo ""
    echo "  💡 Optional (hides 'localhost' on stage): run ONCE,"
    echo "       echo '127.0.0.1 $FANCY_HOST' | sudo tee -a /etc/hosts"
  }
  echo ""
  echo "  (Restart fresh:  fuser -k $PORT/tcp && sudo ./serve.sh)"
  exit 0
fi

echo ""
echo "  PhishGuard demo server -> http://localhost:$PORT"
echo ""
echo "  Open this URL in the browser:"
echo "    $PUBLIC_URL"
echo ""
echo "  Expected: warning banner + password-field alarm + badge."
echo "  Press Ctrl+C to stop."
echo ""

exec python3 -m http.server "$PORT"
