#!/bin/sh

# Choose container runtime: podman or docker
if command -v podman >/dev/null 2>&1; then
    CONTAINER_CMD=podman
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD=docker
else
    echo "Error: Neither podman nor docker is installed." >&2
    exit 1
fi

echo "Using container runtime: $CONTAINER_CMD"

$CONTAINER_CMD run --rm --entrypoint cat fedora:latest /usr/lib/sysimage/rpm/rpmdb.sqlite > testdata/rpmdb.sqlite
$CONTAINER_CMD run --rm --entrypoint cat openeuler/openeuler:20.09 /var/lib/rpm/Packages > testdata/Packages
$CONTAINER_CMD run --rm --entrypoint cat opensuse/leap:15.6 /usr/lib/sysimage/rpm/Packages.db > testdata/Packages.db

