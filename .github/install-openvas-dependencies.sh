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
    lcov \
    libcgreen1-dev \
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
    libroken18-heimdal \
    libhdb9-heimdal \
    libpopt0 \
    && rm -rf /var/lib/apt/lists/*
