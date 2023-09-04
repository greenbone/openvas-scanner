#!/bin/sh
[ -z "$CLEAN" ] && CLEAN=0 
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORK_DIR=$SCRIPT_DIR/../tmp
LIB_VERSION=1.10.2
LIB_NAME=libgcrypt
PREFIX=$SCRIPT_DIR/..
# should be set based on target, TODO set in build.rs based on target arch
export CC=aarch64-linux-gnu-gcc
#CFLAGS='-Os'
export CHOST=arm64

set -ex

[ "$CLEAN" -ne 0 ] && rm -rf "$WORK_DIR"

[ ! -d "$WORKDIR" ] && mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

[ ! -f "$LIB_NAME-$LIB_VERSION.tar.bz2" ] && curl --fail -O https://gnupg.org/ftp/gcrypt/$LIB_NAME/$LIB_NAME-$LIB_VERSION.tar.bz2 
[ ! -d "$LIB_NAME-$LIB_VERSION" ] && tar -xf $LIB_NAME-$LIB_VERSION.tar.bz2
cd $LIB_NAME-$LIB_VERSION

./configure --prefix $PREFIX --host aarch64-unknown-linux-gnu --enable-static --disable-shared
make install
