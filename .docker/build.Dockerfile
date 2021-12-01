ARG VERSION=unstable
# this allows to work on forked repository
ARG REPOSITORY=greenbone/openvas-scanner
FROM $REPOSITORY:$VERSION

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
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
    && rm -rf /var/lib/apt/lists/*
