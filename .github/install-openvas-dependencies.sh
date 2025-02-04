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
    pkg-config \
    libssl-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libjson-glib-dev \
    libksba-dev \
    libpaho-mqtt-dev \
    libpcap-dev \
    libgcrypt-dev \
    libssh-dev \
    libbsd-dev \
    libgnutls30 \
    libgssapi3-heimdal \
    krb5-multidev \
    libasn1-8-heimdal \
    libroken19-heimdal \
    libhdb9-heimdal \
    libpopt0 \
    libcurl4 \
    libcurl4-gnutls-dev \
    libhiredis-dev \
    && rm -rf /var/lib/apt/lists/*

curl -L -o cgreen.tar.gz https://github.com/cgreen-devs/cgreen/archive/refs/tags/1.6.3.tar.gz -k
tar -xzf cgreen.tar.gz && cd cgreen-1.6.3
make install
ldconfig
