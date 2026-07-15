ARG OPENVAS_IMAGE=ghcr.io/greenbone/openvas-scanner:stable
FROM ${OPENVAS_IMAGE}

ARG RUST_VERSION=1.96.0
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:${PATH}

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    ca-certificates \
    capnproto \
    clang \
    cmake \
    curl \
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

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rustup component add clippy rustfmt \
    && git config --system --add safe.directory /workspace

WORKDIR /workspace/rust
