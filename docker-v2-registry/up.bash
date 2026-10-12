#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
registry=127.0.0.1:55000

"${fixture_dir}/down.bash"
podman run \
    --detach \
    --rm \
    --name openvas-docker-v2-registry \
    --publish "${registry}:5000" \
    --volume "${fixture_dir}/auth:/auth:ro,Z" \
    --env REGISTRY_AUTH=htpasswd \
    --env REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    --env REGISTRY_AUTH_HTPASSWD_REALM=Registry \
    docker.io/library/registry:3 >/dev/null

image="$(tar --create --directory "${fixture_dir}/rootfs" . | podman import --quiet -)"
trap 'podman image rm --force "${image}" >/dev/null' EXIT
podman push \
    --quiet \
    --creds openvas-test:openvas-test \
    --tls-verify=false \
    --retry 10 \
    --format v2s2 \
    "${image}" \
    "docker://${registry}/openvas-subrepository/image:latest"
