#!/bin/sh
# To execute: ./start-discovery.sh <target>
# Example: SENSOR=<sensor> ./start-discovery.sh
[ -z "$API_KEY" ] && API_KEY="changeme"
[ -z "$SENSOR" ] && SENSOR="localhost:3000"
[ -z "$1" ] && TARGET="127.0.0.1" || TARGET="$1"
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

payload=$(sed "s/localhost/$TARGET/" "$SCRIPTPATH/discovery.json")
id=$(curl -s -H "Content-Type: application/json" -H "X-Api-Key: $API_KEY" -d "$payload" "$SENSOR/scans" | sed 's/"//g')
echo "Scan ID: $id"
curl --fail-with-body -s -H "Content-Type: application/json" -H "X-Api-Key: $API_KEY" -d '{"action": "start"}' "$SENSOR/scans/$id" || exit 1
echo "Status: curl --fail-with-body -H \"X-Api-Key: $API_KEY\" \"$SENSOR/scans/$id/status\""
echo "Results: curl --fail-with-body -H \"X-Api-Key: $API_KEY\" \"$SENSOR/scans/$id/results\""
