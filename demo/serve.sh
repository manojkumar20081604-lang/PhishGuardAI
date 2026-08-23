#!/usr/bin/env bash
# PhishGuard AI - competition demo server. ONE COMMAND setup.
#
#   ./serve.sh              -> does EVERYTHING (auto-sudo, hosts entry, port 80)
#   ./serve.sh 8020         -> no-sudo fallback dev mode (port shows in URL)
set -euo pipefail
cd "$(dirname "$0")"

FANCY_HOST="secure-login.paypal-verify-alert.top"
URL_PATH="/signin"
PORT="${1:-80}"

# ---- Fallback dev mode (no root needed) -------------------------------------
if [ "$PORT" != "80" ]; then
  HOSTPART="localhost"; PORT_SUFFIX=":$PORT"
else
  # ---- Single-step mode: auto-elevate once, then never ask again ------------
  if [ "$(id -u)" != "0" ]; then
    echo "  🔑 One-time admin rights needed (hosts entry + port 80)..."
    exec sudo -E bash "$0" "$@"
  fi

  # Ensure the realistic hostname resolves to this laptop (idempotent)
  if ! grep -qF "$FANCY_HOST" /etc/hosts; then
    echo "127.0.0.1 $FANCY_HOST" >> /etc/hosts
    echo "  ✅ Added $FANCY_HOST -> this laptop (/etc/hosts)"
  fi
  HOSTPART="$FANCY_HOST"; PORT_SUFFIX=""
fi

check() {
  curl -s -o /dev/null "http://localhost:$PORT$URL_PATH" 2>/dev/null
}

PUBLIC_URL="http://$HOSTPART$PORT_SUFFIX$URL_PATH"

if check; then
  echo ""
  echo "  ✅ Demo server is ALREADY running - nothing to start."
  echo ""
  echo "     Open:  $PUBLIC_URL"
  echo ""
  echo "  (Restart fresh:  fuser -k $PORT/tcp && ./serve.sh)"
  exit 0
fi

echo ""
echo "  PhishGuard demo server ready."
echo ""
echo "  Open this URL in the browser:"
echo "    $PUBLIC_URL"
echo ""
echo "  Expected: warning banner + password-field alarm + badge."
echo "  Press Ctrl+C to stop."
echo ""

exec python3 -m http.server "$PORT"
