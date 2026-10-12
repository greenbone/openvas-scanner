#!/usr/bin/env bash
set -euo pipefail

podman stop --ignore --time 1 openvas-docker-v2-registry >/dev/null
