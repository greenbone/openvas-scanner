# to be built with openvas-scanner top level dir as base

FROM registry.community.greenbone.net/community/gvm-libs:edge

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    redis-server \
    redis-tools \
    curl \
    patchelf \
    gettext-base \
    build-essential \
    cmake \
    make \
    gcc \
    g++ \
    pkg-config \
    bison \
    libglib2.0-dev \
    libgpgme-dev \
    libgnutls28-dev \
    libgcrypt20-dev \
    libpcap-dev \
    libksba-dev \
    libmagic-dev \
    file \
    libssh-dev \
    libhiredis-dev \
    libxml2-dev \
    libnet1-dev \
    libpaho-mqtt-dev \
    libjson-glib-dev \
    libcurl4-gnutls-dev \
    libbsd-dev \
    uuid-dev \
    libldap2-dev \
    libradcli-dev \
    gcc-mingw-w64 \
    rsync \
    nmap \
    libsnmp-dev \
    python3 \
    python3-pip \
    python3-impacket \
    mosquitto \
    && rm -rf /var/lib/apt/lists/*

# Build from src
COPY . /opt/openvas-build/
WORKDIR /opt/openvas-build

RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install

COPY rust/openvasd-tests/entrypoint.sh /entrypoint.sh

COPY .docker/openvas.conf /etc/openvas/
COPY rust/openvasd-tests/openvasd.toml.template /etc/openvas/openvasd.toml.template

RUN chmod +x /entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["/entrypoint.sh"]
