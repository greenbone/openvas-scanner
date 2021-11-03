ARG VERSION=main

FROM greenbone/gvm-libs:$VERSION

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    bison \
    build-essential \
    clang \
    clang-format \
    clang-tools \
    cmake \
    libgnutls28-dev \
    libgpgme-dev \
    libjson-glib-dev \
    libksba-dev \
    libpaho-mqtt-dev \
    libpcap-dev \
    libssh-gcrypt-dev \
    && rm -rf /var/lib/apt/lists/*
