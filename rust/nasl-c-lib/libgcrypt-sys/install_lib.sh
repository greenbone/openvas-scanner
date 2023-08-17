#!/bin/sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORK_DIR=$SCRIPT_DIR/../tmp
LIB_VERSION=1.10.2
LIB_NAME=libgcrypt
PREFIX=$SCRIPT_DIR/..

mkdir -p "$WORK_DIR"
cd "$WORK_DIR" || { echo "fatal error" >&2; rm -rf "$SCRIPT_DIR/../tmp"; exit 1; }

curl -O https://gnupg.org/ftp/gcrypt/$LIB_NAME/$LIB_NAME-$LIB_VERSION.tar.bz2 || { echo "fatal error" >&2; rm -rf "$SCRIPT_DIR/../tmp"; exit 2; }
tar -xf $LIB_NAME-$LIB_VERSION.tar.bz2 || { echo "fatal error" >&2; rm -rf "$SCRIPT_DIR/../tmp"; exit 3; }
cd $LIB_NAME-$LIB_VERSION || { echo "fatal error" >&2; rm -rf "$SCRIPT_DIR/../tmp"; exit 4; }

./configure --prefix $PREFIX --enable-static --disable-shared || { echo "fatal error" >&2; rm -rf "$SCRIPT_DIR/../tmp"; exit 5; }
make install || { echo "fatal error" >&2; rm -rf "$SCRIPT_DIR/../tmp"; exit 6; }

rm -rf "$SCRIPT_DIR/../tmp"
