ARG VERSION=edge
# this allows to override gvm-libs for e.g. smoketests
ARG GVM_LIBS=registry.community.greenbone.net/community/gvm-libs

FROM rust AS rust
COPY . /source
# if we have already binaries available we don't need to build them again
RUN mv /source/.docker/install /install || true
RUN mkdir -p /install/usr/local/bin
RUN ls -las /install/usr/local/bin/
WORKDIR /source/rust
RUN apt update && apt install -y \
    ca-certificates \
    libsnmp-dev
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/source/rust/target \
  [ -f /install/usr/local/bin/openvasd ] && \
  [ -f /install/usr/local/bin/scannerctl ] && \
  [ -f /install/usr/local/bin/feed-verifier ] || \
    ( cargo build --release && \
    install -Dm755 target/release/openvasd /install/usr/local/bin/openvasd && \
    install -Dm755 target/release/scannerctl /install/usr/local/bin/scannerctl && \
    install -Dm755 target/release/feed-verifier /install/usr/local/bin/feed-verifier )

# this is needed when we just want to copy the build binaries onto our dest dir
FROM scratch AS rs-binaries
COPY --from=rust /install /install


FROM greenbone/openvas-smb AS openvas-smb

FROM ${GVM_LIBS}:${VERSION} AS build
COPY . /source
RUN sh /source/.github/install-openvas-dependencies.sh
COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
RUN cmake -DCMAKE_BUILD_TYPE=Release -DINSTALL_OLD_SYNC_SCRIPT=OFF -B/build /source
RUN DESTDIR=/install cmake --build /build -- install


FROM scratch AS prepared
COPY --from=build /install /install
COPY --from=rs-binaries /install/usr/local/bin/openvasd /install/usr/local/bin/openvasd
COPY --from=rs-binaries /install/usr/local/bin/scannerctl /install/usr/local/bin/scannerctl

FROM ${GVM_LIBS}:${VERSION}
# we set the VERSION_CODENAME instead of stable to prevent accidental
# distribution upgrades
RUN  . /etc/os-release && \
  sed -i "s/stable/$VERSION_CODENAME/g" /etc/apt/sources.list.d/*.sources
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
  bison \
  libjson-glib-1.0-0 \
  libksba8 \
  nmap \
  libcap2-bin \
  snmp \
  pnscan \
  libbsd0 \
  rsync \
  # net-tools is required by some nasl plugins.
  # nasl_pread: Failed to execute child process “netstat” (No such file or directory)
  net-tools \
  libgnutls30 \
  libgssapi3-heimdal \
  libkrb5-26-heimdal \
  libasn1-8-heimdal \
  libroken19-heimdal \
  libhdb9-heimdal \
  libpopt0 \
  libcurl4 \
  zlib1g \
  libssh-4 \
  libmagic1t64 \
  libcurl4-gnutls-dev \
  && rm -rf /var/lib/apt/lists/*
COPY .docker/openvas.conf /etc/openvas/



# must be pre built within the rust dir and moved to the bin dir
# usually this image is created within in a ci ensuring that the
# binary is available.
COPY --from=prepared /install/ /
COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
COPY --from=openvas-smb /usr/local/bin/ /usr/local/bin/
RUN ldconfig
# allow openvas to access raw sockets and all kind of network related tasks
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/sbin/openvas
# allow nmap to send e.g. UDP or TCP SYN probes without root permissions
ENV NMAP_PRIVILEGED=1
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
RUN chmod 755 /usr/local/bin/scannerctl
RUN chmod 755 /usr/local/bin/openvasd
RUN mkdir -p /var/lib/openvasd/certs
CMD /usr/local/bin/openvasd
