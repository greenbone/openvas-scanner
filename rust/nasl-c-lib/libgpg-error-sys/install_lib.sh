#!/bin/sh
[ -z "$CLEAN" ] && CLEAN=0 
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORK_DIR=$SCRIPT_DIR/../tmp
LIB_VERSION=1.47
LIB_NAME=libgpg-error
PREFIX=$SCRIPT_DIR/..
set -ex

[ "$CLEAN" -ne 0 ] && rm -rf "$WORK_DIR"

[ ! -d "$WORKDIR" ] && mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

[ ! -f "$LIB_NAME-$LIB_VERSION.tar.bz2" ] && curl --fail -O https://gnupg.org/ftp/gcrypt/$LIB_NAME/$LIB_NAME-$LIB_VERSION.tar.bz2 
[ ! -d "$LIB_NAME-$LIB_VERSION" ] && tar -xf $LIB_NAME-$LIB_VERSION.tar.bz2
cd $LIB_NAME-$LIB_VERSION

./configure --prefix $PREFIX --enable-static --disable-shared
make install

