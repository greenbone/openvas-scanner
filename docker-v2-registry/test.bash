#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${fixture_dir}/.." && pwd)"
registry_port="${OPENVAS_DOCKER_V2_PORT:-55000}"

"${fixture_dir}/up.bash"

export OPENVAS_TEST_DOCKER_V2_REGISTRY="127.0.0.1:${registry_port}"
export CARGO_INCREMENTAL=0

cd "${repository_root}/rust"
cargo test --bin openvasd container_image_scan_docker_v2_subrepository -- --ignored --nocapture
