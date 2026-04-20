#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
FEED="$(pwd)/rust/examples/feed"
CERTS="$(pwd)/compose/certs"
PORT=3000

CONFIG=$(mktemp)
cat > "$CONFIG" <<EOF
[feed]
path = "$FEED/nasl"
signature_check = false
check_interval = "3600s"

[notus]
advisories_path = "$FEED/notus/advisories"
products_path = "$FEED/notus/products"
EOF

cargo build --bin openvasd --manifest-path rust/Cargo.toml
SCANNER_TYPE=openvasd LISTENING="127.0.0.1:$PORT" \
  TLS_CERTS="$CERTS/server.pem" TLS_KEY="$CERTS/server.key" TLS_CLIENT_CERTS="$CERTS/clients/" \
  ./rust/target/debug/openvasd -c "$CONFIG" &
OPENVASD_PID=$!
trap "kill $OPENVASD_PID 2>/dev/null; rm -f $CONFIG" EXIT

CURL="curl -sk --key $CERTS/clients/client1.key --cert $CERTS/clients/client1.pem"

echo "Waiting for openvasd (pid $OPENVASD_PID)..."
for i in $(seq 1 30); do
  $CURL "https://localhost:$PORT/health/alive" && break
  sleep 1
done
echo ""

echo "Waiting for feed sync..."
for i in $(seq 1 30); do
  VTS=$($CURL "https://localhost:$PORT/vts" 2>/dev/null)
  [ "$VTS" != "" ] && [ "$VTS" != "[]" ] && break
  sleep 1
done
echo "VTs: $VTS"

SCAN_ID=$($CURL -X POST -H 'Content-Type: application/json' -d '{
  "target": {"hosts": ["127.0.0.1"], "ports": [{"protocol":"tcp","range":[{"start":22,"end":22}]}]},
  "vts": [{"oid": "0.0.0.0.0.0.0.0.0.1"}]
}' "https://localhost:$PORT/scans" | tr -d '"')
echo "=== Scan: $SCAN_ID ==="

$CURL -X POST -H 'Content-Type: application/json' -d '{"action":"start"}' \
  "https://localhost:$PORT/scans/$SCAN_ID"

for i in $(seq 1 30); do
  STATUS=$($CURL "https://localhost:$PORT/scans/$SCAN_ID/status")
  echo "Status: $STATUS"
  echo "$STATUS" | grep -q '"succeeded"\|"failed"' && break
  sleep 1
done

echo "=== Results ==="
$CURL "https://localhost:$PORT/scans/$SCAN_ID/results"
echo ""
