# This script installs openvas-dependencies assuming that gvm-libs is already installed.
# Usually it is run within a gvm-libs image.
#/bin/sh
set -ex
# TODO: create a better structure on various install list to not have to add runtime
# dependencies into the Dockfile, which can easily overlooked.
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
    libsnmp-dev \
    libgssapi3-heimdal \
    krb5-multidev \
    libasn1-8-heimdal \
    libroken19-heimdal \
    libhdb9-heimdal \
    libpopt0 \
    libcurl4 \
    libcurl4-gnutls-dev \
    libhiredis-dev \
    libmagic-dev \
    libcgreen1-dev \
    && rm -rf /var/lib/apt/lists/*

ldconfig
