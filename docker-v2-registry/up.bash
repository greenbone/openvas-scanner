#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
container_name="${OPENVAS_DOCKER_V2_CONTAINER:-openvas-docker-v2-subrepository}"
registry_port="${OPENVAS_DOCKER_V2_PORT:-55000}"
registry_address="127.0.0.1:${registry_port}"
registry_url="http://${registry_address}"
temporary_directory="$(mktemp -d)"

cleanup() {
    rm -r -- "${temporary_directory}"
}

trap cleanup EXIT

command -v podman >/dev/null
command -v curl >/dev/null
command -v gzip >/dev/null
command -v sha256sum >/dev/null
command -v tar >/dev/null

if podman container exists "${container_name}"; then
    if [[ "$(podman inspect --format '{{.State.Running}}' "${container_name}")" != "true" ]]; then
        podman start "${container_name}" >/dev/null
    fi
else
    podman run \
        --detach \
        --rm \
        --name "${container_name}" \
        --publish "127.0.0.1:${registry_port}:5000" \
        docker.io/library/registry:2 >/dev/null
fi

for _ in $(seq 1 50); do
    if curl --fail --silent --show-error "${registry_url}/v2/" >/dev/null; then
        break
    fi
    sleep 0.1
done

curl --fail --silent --show-error "${registry_url}/v2/" >/dev/null

tar \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --create \
    --file "${temporary_directory}/layer.tar" \
    --directory "${fixture_dir}/rootfs" \
    .
gzip --no-name --stdout "${temporary_directory}/layer.tar" >"${temporary_directory}/layer.tar.gz"

layer_diff_id="$(sha256sum "${temporary_directory}/layer.tar" | cut -d ' ' -f 1)"
printf '{"architecture":"amd64","config":{"Labels":null},"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}\n' \
    "${layer_diff_id}" >"${temporary_directory}/config.json"

config_digest="sha256:$(sha256sum "${temporary_directory}/config.json" | cut -d ' ' -f 1)"
config_size="$(stat --format '%s' "${temporary_directory}/config.json")"
layer_digest="sha256:$(sha256sum "${temporary_directory}/layer.tar.gz" | cut -d ' ' -f 1)"
layer_size="$(stat --format '%s' "${temporary_directory}/layer.tar.gz")"

printf '{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"%s"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":%s,"digest":"%s"}]}\n' \
    "${config_size}" \
    "${config_digest}" \
    "${layer_size}" \
    "${layer_digest}" >"${temporary_directory}/manifest.json"

upload_blob() {
    local repository="$1"
    local path="$2"
    local digest="$3"
    local location
    local separator

    curl \
        --fail \
        --silent \
        --show-error \
        --dump-header "${temporary_directory}/headers" \
        --output /dev/null \
        --request POST \
        "${registry_url}/v2/${repository}/blobs/uploads/"

    location="$(awk 'tolower($1) == "location:" { sub(/\r$/, "", $2); print $2 }' "${temporary_directory}/headers" | tail -n 1)"
    if [[ "${location}" == /* ]]; then
        location="${registry_url}${location}"
    fi
    if [[ "${location}" == *\?* ]]; then
        separator='&'
    else
        separator='?'
    fi

    curl \
        --fail \
        --silent \
        --show-error \
        --output /dev/null \
        --request PUT \
        --header 'Content-Type: application/octet-stream' \
        --data-binary "@${path}" \
        "${location}${separator}digest=${digest}"
}

put_image() {
    local repository="$1"
    local tag="$2"

    upload_blob "${repository}" "${temporary_directory}/config.json" "${config_digest}"
    upload_blob "${repository}" "${temporary_directory}/layer.tar.gz" "${layer_digest}"
    curl \
        --fail \
        --silent \
        --show-error \
        --output /dev/null \
        --request PUT \
        --header 'Content-Type: application/vnd.docker.distribution.manifest.v2+json' \
        --data-binary "@${temporary_directory}/manifest.json" \
        "${registry_url}/v2/${repository}/manifests/${tag}"
}

put_image "openvas-subrepository/image-a" "latest"
put_image "openvas-subrepository/image-a" "v1"
put_image "openvas-subrepository/nested/image-b" "latest"

echo "Registry API: ${registry_url}/v2/"
echo "Scan target:  oci://${registry_address}/openvas-subrepository"
echo "Catalog:      $(curl --fail --silent --show-error "${registry_url}/v2/_catalog")"
