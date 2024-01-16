# This script installs openvas-dependencies assuming that gvm-libs is already installed.
# Usually it is run within a gvm-libs image.
#/bin/sh
set -ex
apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    bison \
    build-essential \
    clang \
    clang-format \
    clang-tools \
    cmake \
    curl \
    git \
    lcov \
    libgnutls28-dev \
    libgpgme-dev \
    libjson-glib-dev \
    libksba-dev \
    libpaho-mqtt-dev \
    libpcap-dev \
    libssh-gcrypt-dev \
    libbsd-dev \
    libgnutls30 \
    libgssapi3-heimdal \
    libkrb5-26-heimdal \
    libasn1-8-heimdal \
    libroken19-heimdal \
    libhdb9-heimdal \
    libpopt0 \
    libcurl4 \
    libcurl4-gnutls-dev \
    libhiredis0.14 \
    && rm -rf /var/lib/apt/lists/*

curl -L -o cgreen.tar.gz https://github.com/cgreen-devs/cgreen/archive/refs/tags/1.6.2.tar.gz -k
tar -xzf cgreen.tar.gz && cd cgreen-1.6.2
make install
ldconfig
