FROM rust:1.96.0

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    ca-certificates \
    capnproto \
    clang \
    cmake \
    git \
    libclang-dev \
    libpcap-dev \
    libsnmp-dev \
    libsqlite3-dev \
    libssl-dev \
    make \
    perl \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt \
    && git config --system --add safe.directory /workspace

WORKDIR /workspace/rust
