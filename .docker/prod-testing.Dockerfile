ARG VERSION=edge
# this allows to work on forked repository
ARG REPOSITORY=greenbone/openvas-scanner
ARG GVM_LIBS_VERSION=testing-edge

FROM greenbone/openvas-smb:testing-edge AS openvas-smb
FROM rust AS rust

FROM registry.community.greenbone.net/community/gvm-libs:${GVM_LIBS_VERSION} AS build
COPY . /source
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
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
    libgcrypt-dev \
    libssh-dev \
    libbsd-dev \
    libgnutls30t64 \
    libgssapi3-heimdal \
    libkrb5-26-heimdal \
    libasn1-8-heimdal \
    libroken19-heimdal \
    libhdb9-heimdal \
    libpopt0 \
    libcurl4 \
    libcurl4-gnutls-dev \
    libhiredis-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
RUN cmake -DCMAKE_BUILD_TYPE=Release -DINSTALL_OLD_SYNC_SCRIPT=OFF -B/build /source
RUN DESTDIR=/install cmake --build /build -- install

COPY --from=rust /usr/local/cargo/ /usr/local/cargo/
COPY --from=rust /usr/local/rustup/ /usr/local/rustup/
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN apt update && apt install -y ca-certificates
RUN cargo build --release
RUN cp target/release/openvasd /install/usr/local/bin
RUN cp target/release/scannerctl /install/usr/local/bin

FROM registry.community.greenbone.net/community/gvm-libs:${GVM_LIBS_VERSION}
RUN apt-get update
RUN apt-get install --no-install-recommends --no-install-suggests -y \
  bison \
  libglib2.0-0t64 \
  libjson-glib-1.0-0 \
  libksba8 \
  nmap \
  libcap2-bin \
  snmp \
  # not available in debian:testing 2024-04-29
  # netdiag \
  pnscan \
  libbsd0 \
  rsync \
  # net-tools is required by some nasl plugins.
  # nasl_pread: Failed to execute child process “netstat” (No such file or directory)
  net-tools \
  # for openvas-smb support
  python3-impacket \
  libgnutls30t64 \
  libgssapi3-heimdal \
  libkrb5-26-heimdal \
  libasn1-8-heimdal \
  libroken19-heimdal \
  libhdb9-heimdal \
  libpopt0 \
  libcurl4 \
  libhiredis1.1.0 \
  libcurl3t64-gnutls \
  zlib1g
RUN rm -rf /var/lib/apt/lists/*
COPY .docker/openvas.conf /etc/openvas/
COPY --from=build /install/ /
COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
COPY --from=openvas-smb /usr/local/bin/ /usr/local/bin/
RUN ldconfig
# allow openvas to access raw sockets and all kind of network related tasks
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/sbin/openvas
# allow nmap to send e.g. UDP or TCP SYN probes without root permissions
ENV NMAP_PRIVILEGED=1
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
