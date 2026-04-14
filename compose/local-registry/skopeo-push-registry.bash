#!/usr/bin/env bash
set -e

# debug marker (change this to verify rebuilds)
echo "gosh i hate infrastructure"

# configurable variables (can be overridden via env)
REGISTRY="${REGISTRY:-registry:5000}"
USERNAME="${USERNAME:-dummy}"
PASSWORD="${PASSWORD:-dummy}"

IMAGES="${IMAGES:-\
docker.io/nichtsfrei/victim:latest \
docker.io/openeuler/openeuler:latest \
docker.io/openeuler/openeuler:24.03-lts-sp1 \
docker.io/openeuler/openeuler:20.03-lts-sp4\
}"

echo "Using registry: $REGISTRY"
echo "Images: $IMAGES"

skopeo login \
  --tls-verify=false \
  --username "$USERNAME" \
  --password "$PASSWORD" \
  "$REGISTRY"

for img in $IMAGES; do
  name=${img#docker.io/}
  echo "Copying $img -> $REGISTRY/$name"

  skopeo copy \
    --dest-tls-verify=false \
    "docker://$img" \
    "docker://$REGISTRY/$name"
done

touch /state/push-done
