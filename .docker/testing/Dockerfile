# Dockerfile for openvas-scanner-$VERSION-$COMPILER-testing

# Define ARG we use through the build
ARG VERSION=master
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

FROM greenbone/eulabeia-c-lib
RUN apt-get update \
    && apt-get install --no-install-recommends --assume-yes \
    ca-certificates \
    build-essential \
    cmake \
    clang-tools \
    git \
    libglib2.0-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libhiredis-dev \
    libpcap-dev \
    libssh-gcrypt-dev \
    libxml2-dev \
    libnet1-dev \
    make \
    pkg-config \
    uuid-dev \
    libssl-dev \
    lcov \
    libical-dev \
    libpq-dev \
    libnet1-dev \
    postgresql-server-dev-all \
    xsltproc \
    bison \
    libksba-dev \
    libpcap-dev \
    libjson-glib-dev \
    libeulabeia-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src

RUN git clone --depth 1 https://github.com/cgreen-devs/cgreen.git \
    && cd cgreen \
    && make \
    && make test \
    && make install \
    && cd .. \
    && rm -rf cgreen
    
RUN git clone --depth 1 https://github.com/eclipse/paho.mqtt.c \
    && cd paho.mqtt.c \
    && make \
    && make install \
    && cd .. \
    && rm -rf paho.mqtt.c; \
