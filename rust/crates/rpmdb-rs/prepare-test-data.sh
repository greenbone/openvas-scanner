#!/bin/sh
set -ex
# Choose container runtime: podman or docker
if command -v podman >/dev/null 2>&1; then
    CONTAINER_CMD=podman
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD=docker
fi

fetch_via_script() {
    image="$1"
    file="$2"
    target="$3"
    workdir="$(mktemp -d)"
    # TODO: move file to argument in download-frozen-image-v2
    echo "downloading $workdir $image"
    bash download-frozen-image-v2.sh "$file" "$workdir" "$image"
    echo "downloaded"
    mv "$workdir/$file" "$target"
    echo "moved "
    rm -rf "$workdir"
}

fetch_via_command() {
    image="$1"
    file="/$2"
    target="$3"
    $CONTAINER_CMD run --rm --entrypoint cat $image $file > $target
}

fetch() {
    image="$1"
    file="$2"
    target="testdata/$(basename $file)"
    if [ ! -e "$target" ]; then
	echo "downloading $target"
	if [ -z "$CONTAINER_CMD" ]; then
	    fetch_via_script "$image" "$file" "$target"
	else
	    fetch_via_command "$image" "$file" "$target"
	fi
    else
	echo "$target exists"
    fi

}


fetch "fedora:latest" "usr/lib/sysimage/rpm/rpmdb.sqlite" 
fetch "openeuler/openeuler:20.09" "var/lib/rpm/Packages"
fetch "opensuse/leap:15.6" "usr/lib/sysimage/rpm/Packages.db"
