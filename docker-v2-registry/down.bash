#!/usr/bin/env bash
set -euo pipefail

container_name="${OPENVAS_DOCKER_V2_CONTAINER:-openvas-docker-v2-subrepository}"

if podman container exists "${container_name}"; then
    podman stop --time 1 "${container_name}" >/dev/null
fi
