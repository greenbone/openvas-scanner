#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
#
# Generate OpenVAS reference snapshots for the openvasd compatibility tests.
#
# This deliberately reuses the existing compose smoketest environment instead of
# starting a second local OpenVAS/openvasd setup. It will bring up the same stack
# as `make -C compose test-environment-running`, inject the fixture feed files
# for each case, run the scan through the public API, and write one raw
# reference JSON to rust/data/tests/scans/snapshots/<case>/snapshot.json.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/../../../.." && pwd)
COMPOSE_DIR=${COMPOSE_DIR:-"$REPO_DIR/compose"}
SCANS_DIR=${SCANS_DIR:-"$SCRIPT_DIR/scans"}
SNAPSHOTS_DIR=${SNAPSHOTS_DIR:-"$SCRIPT_DIR/snapshots"}
RUN_SCAN_HURL=${RUN_SCAN_HURL:-"$SCRIPT_DIR/run-openvas-snapshot.hurl"}
GET_STATUS_HURL=${GET_STATUS_HURL:-"$SCRIPT_DIR/get-scan-status.hurl"}
OPENVASD_SERVER=${OPENVASD_SERVER:-"https://localhost:3000"}
CLIENT_KEY=${CLIENT_KEY:-"$COMPOSE_DIR/certs/clients/client1.key"}
CLIENT_CERT=${CLIENT_CERT:-"$COMPOSE_DIR/certs/clients/client1.pem"}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-600}
POLL_SECONDS=${POLL_SECONDS:-1}
START_ENVIRONMENT=${START_ENVIRONMENT:-1}
USE_LOCAL_IMAGE=${USE_LOCAL_IMAGE:-1}
DOWN_AFTER=${DOWN_AFTER:-0}
PREPARE_ONLY=${PREPARE_ONLY:-0}
DISABLE_OPENVAS_SIGNATURE_CHECK=${DISABLE_OPENVAS_SIGNATURE_CHECK:-1}
REDIS_URL=${REDIS_URL:-"unix:///run/redis/redis.sock"}
REMOTE_FEED_DIR=${REMOTE_FEED_DIR:-"/tmp/openvas-compat-feed"}
REMOTE_PLUGIN_DIR=${REMOTE_PLUGIN_DIR:-"/var/lib/openvas/plugins"}
COMPOSE_FILE_ARGS=${COMPOSE_FILE_ARGS:-"-f base.yaml -f mtls.yaml -f tests/victim.yaml -f local-registry.yaml"}

usage() {
  cat <<EOF
Usage: $(basename "$0") [case ...]

Generates OpenVAS snapshots for scan cases in:
  $SCANS_DIR

This uses the existing compose smoketest stack, so it is directly runnable from
this repository and does not require a separate manual OpenVAS setup.

Environment:
  START_ENVIRONMENT=0  Do not run compose startup first; reuse an already running stack.
  USE_LOCAL_IMAGE=0    Use compose's test-environment-running target with OPENVAS_IMAGE.
                       Default uses local-test-environment-running, like smoketest.
  DOWN_AFTER=1         Stop compose environment and remove volumes after generation.
  PREPARE_ONLY=1       Only inject the fixture feed and load metadata; do not run scans.
  DISABLE_OPENVAS_SIGNATURE_CHECK=0
                       Keep classic OpenVAS NASL signature checking enabled.
                       Default disables it so unsigned fixture NASLs can run.
  RUN_SCAN_HURL=PATH   Hurl flow for scan creation/start/results. Default: $RUN_SCAN_HURL
  GET_STATUS_HURL=PATH Hurl request for final scan status. Default: $GET_STATUS_HURL
  OPENVASD_SERVER=URL  API URL. Default: $OPENVASD_SERVER
  CLIENT_KEY=PATH      mTLS client key. Default: $CLIENT_KEY
  CLIENT_CERT=PATH     mTLS client certificate. Default: $CLIENT_CERT
  TIMEOUT_SECONDS=N    Per-scan wait timeout. Default: $TIMEOUT_SECONDS
  REDIS_URL=URL        Redis URL inside openvasd container. Default: $REDIS_URL
  COMPOSE_FILE_ARGS    Compose file arguments used to find containers.
                       Default: $COMPOSE_FILE_ARGS
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_cmd curl
require_cmd hurl
require_cmd jq
require_cmd sha256sum
require_cmd make

if docker compose version >/dev/null 2>&1; then
  ENGINE=docker
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  ENGINE=docker
  COMPOSE=(docker-compose)
else
  require_cmd podman-compose
  ENGINE=podman
  COMPOSE=(podman-compose)
fi

COMPOSE_FILES=($COMPOSE_FILE_ARGS)

compose_cmd() {
  (cd "$COMPOSE_DIR" && "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" "$@")
}

container_id() {
  compose_cmd ps -q "$1"
}

api_curl() {
  curl -k --key "$CLIENT_KEY" --cert "$CLIENT_CERT" "$@"
}

hurl_api() {
  hurl -k --file-root "$SCRIPT_DIR" --key "$CLIENT_KEY" --cert "$CLIENT_CERT" "$@"
}

wait_for_api() {
  local deadline=$((SECONDS + 3600))
  until api_curl -fsS -I -o /dev/null "$OPENVASD_SERVER/health/started"; do
    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for openvasd API at $OPENVASD_SERVER" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_case_vts() {
  local scan_json=$1
  local output=$2
  local deadline=$((SECONDS + TIMEOUT_SECONDS))

  until api_curl --max-time "$TIMEOUT_SECONDS" -fsS -o "$output" "$OPENVASD_SERVER/vts" \
    && jq -e --slurpfile available "$output" \
      'all(.vts[].oid; . as $oid | $available[0] | index($oid))' \
      "$scan_json" >/dev/null
  do
    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for fixture VTs from $scan_json to become available" >&2
      return 1
    fi
    sleep "$POLL_SECONDS"
  done
}

start_environment() {
  if [[ "$START_ENVIRONMENT" != "1" ]]; then
    return
  fi

  if [[ "$USE_LOCAL_IMAGE" == "1" ]]; then
    make -C "$COMPOSE_DIR" local-test-environment-running
  else
    make -C "$COMPOSE_DIR" test-environment-running
  fi
}

maybe_down() {
  if [[ "$DOWN_AFTER" == "1" ]]; then
    make -C "$COMPOSE_DIR" test-environment-down
  fi
}

make_case_feed() {
  local case_dir=$1
  local feed_dir=$2
  local files=()
  mkdir -p "$feed_dir"

  mapfile -d '' files < <(cd "$case_dir" && find . -type f \( -name '*.nasl' -o -name '*.inc' \) -print0)
  for file in "${files[@]}"; do
    mkdir -p "$feed_dir/$(dirname "$file")"
    cp "$case_dir/$file" "$feed_dir/$file"
  done

  if [[ ! -f "$feed_dir/plugin_feed_info.inc" ]]; then
    cat > "$feed_dir/plugin_feed_info.inc" <<'EOF'
PLUGIN_SET = "202605270000";
PLUGIN_FEED = "OpenVAS compatibility tests";
FEED_VENDOR = "Greenbone AG";
FEED_HOME = "https://www.greenbone.net/";
FEED_NAME = "OpenVASCompatibilityTests";
EOF
  fi

  (cd "$feed_dir" && find . -type f ! -name sha256sums -printf '%P\n' | sort | xargs -r sha256sum > sha256sums)
}

copy_into_service() {
  local service=$1 src=$2 dst=$3
  local cid
  cid=$(container_id "$service")
  [[ -n "$cid" ]] || { echo "$service container is not running" >&2; exit 1; }
  "$ENGINE" cp "$src" "$cid:$dst"
}

copy_into_container() {
  copy_into_service openvasd "$@"
}

exec_openvasd() {
  compose_cmd exec -T openvasd "$@"
}

exec_openvas() {
  compose_cmd exec -T openvas "$@"
}

disable_openvas_signature_check() {
  if [[ "$DISABLE_OPENVAS_SIGNATURE_CHECK" != "1" ]]; then
    return
  fi

  echo "    disabling classic OpenVAS NASL signature check for fixture runs"
  exec_openvasd sh -c '
    conf=/etc/openvas/openvas.conf
    touch "$conf"
    if grep -q "^nasl_no_signature_check[[:space:]]*=" "$conf"; then
      sed -i "s/^nasl_no_signature_check[[:space:]]*=.*/nasl_no_signature_check = yes/" "$conf"
    else
      printf "\nnasl_no_signature_check = yes\n" >> "$conf"
    fi
  '
}

inject_case_feed() {
  local feed_dir=$1
  local source_dir=${2:-$feed_dir}
  local files=()

  echo "    injecting fixture feed into compose openvasd container"
  exec_openvasd sh -c "rm -rf '$REMOTE_FEED_DIR' && mkdir -p '$REMOTE_FEED_DIR'"
  copy_into_container "$feed_dir/." "$REMOTE_FEED_DIR/"
  exec_openvasd sh -c "
    scannerctl feed transform --path '$REMOTE_FEED_DIR' > '$REMOTE_FEED_DIR/vt-metadata.json'
    cd '$REMOTE_FEED_DIR'
    sha256sum vt-metadata.json >> sha256sums
  "

  # OpenVAS executes by filename from its normal plugins folder. Keep the full
  # mounted feed intact and add/overwrite only the fixture NASL/INC files.
  mapfile -d '' files < <(cd "$source_dir" && find . -type f \( -name '*.nasl' -o -name '*.inc' \) -print0)
  for file in "${files[@]}"; do
    local dir
    dir=$(dirname "$file")
    exec_openvasd sh -c "mkdir -p '$REMOTE_PLUGIN_DIR/$dir'"
    copy_into_container "$source_dir/$file" "$REMOTE_PLUGIN_DIR/$file"
    exec_openvas sh -c "mkdir -p '$REMOTE_PLUGIN_DIR/$dir'"
    copy_into_service openvas "$source_dir/$file" "$REMOTE_PLUGIN_DIR/$file"
  done

  echo "    loading fixture metadata into OpenVAS Redis cache"
  exec_openvasd scannerctl feed update --vts-only --vts-path "$REMOTE_FEED_DIR" --redis "$REDIS_URL"
}

run_case() {
  local case_name=$1
  local case_dir="$SCANS_DIR/$case_name"
  local scan_json="$case_dir/scan.json"
  local snapshot_dir="$SNAPSHOTS_DIR/$case_name"

  [[ -d "$case_dir" ]] || { echo "No such case: $case_name" >&2; return 1; }
  [[ -f "$scan_json" ]] || { echo "Missing $scan_json" >&2; return 1; }

  echo "==> $case_name"
  mkdir -p "$snapshot_dir"

  local tmp
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/openvas-compat-$case_name.XXXXXX")
  trap 'rm -rf "$tmp"' RETURN

  local feed_dir="$tmp/feed"
  make_case_feed "$case_dir" "$feed_dir"
  inject_case_feed "$feed_dir" "$case_dir"

  if [[ "$PREPARE_ONLY" == "1" ]]; then
    wait_for_case_vts "$scan_json" "$tmp/vts.json"
    echo "    prepared fixture feed"
    return
  fi

  local configured_scan_id
  configured_scan_id=$(jq -r '.scan_id // empty' "$scan_json")
  if [[ -z "$configured_scan_id" ]]; then
    echo "Missing scan_id in $scan_json; snapshot generation uses it for Hurl variables" >&2
    return 1
  fi
  api_curl -fsS -o /dev/null -X DELETE "$OPENVASD_SERVER/scans/$configured_scan_id" || true

  local retry_count retry_interval_ms
  retry_count=$((TIMEOUT_SECONDS / POLL_SECONDS))
  if (( retry_count < 1 )); then
    retry_count=1
  fi
  retry_interval_ms=$((POLL_SECONDS * 1000))

  echo "    running scan with Hurl ($configured_scan_id)"
  hurl_api \
    --variable "server=$OPENVASD_SERVER" \
    --variable "scan_config=$scan_json" \
    --variable "scan_id=$configured_scan_id" \
    --variable "retry_count=$retry_count" \
    --variable "retry_interval_ms=$retry_interval_ms" \
    --output "$tmp/results.json" \
    "$RUN_SCAN_HURL"
  hurl_api \
    --variable "server=$OPENVASD_SERVER" \
    --variable "scan_id=$configured_scan_id" \
    --output "$tmp/status.json" \
    "$GET_STATUS_HURL"

  jq -n -S --arg scan_id "$configured_scan_id" \
    --slurpfile status "$tmp/status.json" \
    --slurpfile results "$tmp/results.json" \
    '{scan_id: $scan_id, status: $status[0], results: $results[0]}' \
    > "$snapshot_dir/snapshot.json"

  echo "    wrote $snapshot_dir/snapshot.json (final status: succeeded)"
  api_curl -fsS -o /dev/null -X DELETE "$OPENVASD_SERVER/scans/$configured_scan_id" || true
}

mkdir -p "$SNAPSHOTS_DIR"
start_environment
trap maybe_down EXIT
wait_for_api
disable_openvas_signature_check

cases=("$@")
if (( ${#cases[@]} == 0 )); then
  mapfile -t cases < <(find "$SCANS_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
fi

if (( ${#cases[@]} == 0 )); then
  echo "No scan cases found in $SCANS_DIR" >&2
  exit 1
fi

for case_name in "${cases[@]}"; do
  run_case "$case_name"
done
