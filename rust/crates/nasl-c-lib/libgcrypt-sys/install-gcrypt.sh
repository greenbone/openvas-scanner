#!/bin/sh
[ -z "$CLEAN" ] && CLEAN=0 
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

WORK_DIR=$SCRIPT_DIR/../tmp
PREFIX=$SCRIPT_DIR/..

set -ex
if [ "$TARGET" = "aarch64-unknown-linux-gnu" ] && [ "$IN_CROSS" = "1" ]; then
	export CC=aarch64-linux-gnu-gcc
	export CHOST=arm64
	export HOST="--host aarch64-unknown-linux-gnu"
fi

install_gnu() {
	VERSION="$2"
	NAME="$1"
	cd "$WORK_DIR"
	[ ! -f "$NAME-$VERSION.tar.bz2" ] && curl --fail -O https://gnupg.org/ftp/gcrypt/$NAME/$NAME-$VERSION.tar.bz2 
	[ ! -d "$NAME-$VERSION" ] && tar -xf $NAME-$VERSION.tar.bz2
	cd $NAME-$VERSION
	./configure --prefix $PREFIX --enable-static --with-pic --disable-shared $HOST
	make install
}

[ "$CLEAN" -ne 0 ] && rm -rf "$WORK_DIR"
[ ! -d "$WORKDIR" ] && mkdir -p "$WORK_DIR"

install_gnu  "libgpg-error" "1.47"
install_gnu  "libgcrypt" "1.10.2"
