#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
trap '"${fixture_dir}/down.bash"' EXIT
"${fixture_dir}/up.bash"

cd "${fixture_dir}/../rust"
OPENVAS_TEST_DOCKER_V2_REGISTRY=127.0.0.1:55000 \
    cargo test --bin openvasd container_image_scan_docker_v2_subrepository -- --ignored
