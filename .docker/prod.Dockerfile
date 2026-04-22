ARG VERSION=latest
# this allows to override gvm-libs for e.g. smoketests
ARG GVM_LIBS=ghcr.io/greenbone/gvm-libs
ARG RUST_IMAGE=rust
ARG OPENVAS_SMB_IMAGE=greenbone/openvas-smb
ARG BUILD_IMAGE=${GVM_LIBS}:${VERSION}
ARG FINAL_IMAGE=${GVM_LIBS}:${VERSION}
ARG FINAL_PACKAGE_SET=${VERSION}

FROM ${RUST_IMAGE} AS krb5-build
ARG KRB5_VERSION=1.22.2

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    bison \
    ca-certificates \
    curl \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN KRB5_SERIES="${KRB5_VERSION%.*}" \
    && curl --fail -L -O "https://kerberos.org/dist/krb5/${KRB5_SERIES}/krb5-${KRB5_VERSION}.tar.gz" \
    && tar -xzf "krb5-${KRB5_VERSION}.tar.gz"
# Build only the MIT krb5 subtrees that produce the static archives and
# headers used by the Rust build; the full tree pulls in broken utility
# targets we do not need here.
WORKDIR "/tmp/krb5-${KRB5_VERSION}/src"
RUN ./configure --prefix=/opt/krb5-static \
        --enable-static \
        --disable-shared \
        --without-system-verto \
        --without-libedit \
        --disable-rpath \
    && make -C util/support -j"$(nproc)" \
    && make -C util/et -j"$(nproc)" \
    && make -C util/profile -j"$(nproc)" \
    && make -C include -j"$(nproc)" \
    && make -C lib/crypto -j"$(nproc)" \
    && make -C lib/krb5 -j"$(nproc)" \
    && make -C lib/gssapi -j"$(nproc)" \
    && make install-mkdirs \
    && make -C util/support install \
    && make -C util/et install \
    && make -C util/profile install \
    && make -C include install \
    && make -C lib/crypto install \
    && make -C lib/krb5 install \
    && make -C lib/gssapi install \
    && test -f /opt/krb5-static/lib/libgssapi_krb5.a \
    && test -f /opt/krb5-static/lib/libkrb5.a \
    && test -f /opt/krb5-static/lib/libk5crypto.a \
    && test -f /opt/krb5-static/lib/libcom_err.a \
    && test -f /opt/krb5-static/lib/libkrb5support.a

FROM ${RUST_IMAGE} AS pcap-build
ARG LIBPCAP_VERSION=1.10.6

# Debian's static libpcap from `apt-get install libpcap-dev` pulls in
# libsystemd.a and libdbus-1.a. Build libpcap from source instead so the
# Rust binaries do not need those unused static link dependencies.
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    bison \
    ca-certificates \
    curl \
    flex \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN curl --fail -L -O "https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz" \
    && tar -xzf "libpcap-${LIBPCAP_VERSION}.tar.gz"

WORKDIR "/tmp/libpcap-${LIBPCAP_VERSION}"
RUN ./configure --prefix=/opt/libpcap-static \
        --disable-shared \
        --disable-dbus \
    && make -j"$(nproc)" \
    && make install \
    && test -f /opt/libpcap-static/lib/libpcap.a \
    && test -f /opt/libpcap-static/include/pcap.h

FROM ${RUST_IMAGE} AS build-archives

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    libgcrypt20-dev \
    libgpg-error-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=krb5-build /opt/krb5-static /opt/krb5-static
COPY --from=pcap-build /opt/libpcap-static /opt/libpcap-static

RUN DEB_HOST_MULTIARCH="$(gcc -print-multiarch)" \
    && mkdir -p /archives/include/gssapi /archives/include/krb5 \
    && install -m 644 "/usr/lib/${DEB_HOST_MULTIARCH}/libgcrypt.a" /archives/libgcrypt.a \
    && install -m 644 "/usr/lib/${DEB_HOST_MULTIARCH}/libgpg-error.a" /archives/libgpg-error.a \
    && install -m 644 /opt/libpcap-static/lib/libpcap.a /archives/libpcap.a \
    && install -m 644 /opt/krb5-static/lib/libgssapi_krb5.a /archives/libgssapi_krb5.a \
    && install -m 644 /opt/krb5-static/lib/libkrb5.a /archives/libkrb5.a \
    && install -m 644 /opt/krb5-static/lib/libk5crypto.a /archives/libk5crypto.a \
    && install -m 644 /opt/krb5-static/lib/libcom_err.a /archives/libcom_err.a \
    && install -m 644 /opt/krb5-static/lib/libkrb5support.a /archives/libkrb5support.a \
    && install -m 644 /usr/include/gcrypt.h /archives/include/gcrypt.h \
    && install -m 644 "/usr/include/${DEB_HOST_MULTIARCH}/gpg-error.h" /archives/include/gpg-error.h \
    && install -m 644 /opt/libpcap-static/include/pcap.h /archives/include/pcap.h \
    && install -m 644 /opt/krb5-static/include/krb5.h /archives/include/krb5.h \
    && install -m 644 /opt/krb5-static/include/com_err.h /archives/include/com_err.h \
    && install -m 644 /opt/krb5-static/include/profile.h /archives/include/profile.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi.h /archives/include/gssapi/gssapi.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_alloc.h /archives/include/gssapi/gssapi_alloc.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_ext.h /archives/include/gssapi/gssapi_ext.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_generic.h /archives/include/gssapi/gssapi_generic.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_krb5.h /archives/include/gssapi/gssapi_krb5.h \
    && install -m 644 /opt/krb5-static/include/gssapi/mechglue.h /archives/include/gssapi/mechglue.h \
    && install -m 644 /opt/krb5-static/include/krb5/krb5.h /archives/include/krb5/krb5.h

FROM ${RUST_IMAGE} AS rust
ARG BIN_VERSION
ENV BIN_VERSION=${BIN_VERSION}
COPY . /source
COPY --from=build-archives /archives /archives
# if we have already binaries available we don't need to build them again
RUN mv /source/.docker/install /install || true
RUN mkdir -p /install/usr/local/bin
RUN ls -las /install/usr/local/bin/
WORKDIR /source/rust
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    capnproto \
    ca-certificates \
    libclang-dev \
    libsnmp-dev \
    && rm -rf /var/lib/apt/lists/*
ENV OPENVAS_ARCHIVES=/archives \
    LIBPCAP_LIBDIR=/archives

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/source/rust/target \
  [ -f /install/usr/local/bin/openvasd ] && \
  [ -f /install/usr/local/bin/scannerctl ] || \
    ( cargo build --release && \
    install -Dm755 target/release/openvasd /install/usr/local/bin/openvasd && \
    install -Dm755 target/release/scannerctl /install/usr/local/bin/scannerctl )

# this is needed when we just want to copy the build binaries onto our dest dir
FROM scratch AS rs-binaries
COPY --from=rust /install /install

FROM ${OPENVAS_SMB_IMAGE} AS openvas-smb

FROM ${BUILD_IMAGE} AS build
COPY . /source
RUN sh /source/.github/install-openvas-dependencies.sh
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    capnproto \
    && rm -rf /var/lib/apt/lists/*
COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
RUN cmake -DCMAKE_BUILD_TYPE=Release -DINSTALL_OLD_SYNC_SCRIPT=OFF -B/build /source
RUN DESTDIR=/install cmake --build /build -- install

FROM scratch AS prepared
COPY --from=build /install /install
COPY --from=rs-binaries /install/usr/local/bin/openvasd /install/usr/local/bin/openvasd
COPY --from=rs-binaries /install/usr/local/bin/scannerctl /install/usr/local/bin/scannerctl

FROM ${FINAL_IMAGE}
ARG VERSION
ARG FINAL_PACKAGE_SET
COPY .docker/packages /tmp/openvas-packages
# We rewrite suite aliases to VERSION_CODENAME for fixed-release images.
# Edge/testing-style tags skip that rewrite on purpose.
RUN if ! printf '%s' "${VERSION}" | grep -q -- '-edge$'; then \
      suite_name="${VERSION}"; \
      if [ "${suite_name}" = "latest" ]; then suite_name=stable; fi; \
      . /etc/os-release && sed -i "s/${suite_name}/$VERSION_CODENAME/g" /etc/apt/sources.list.d/*.sources; \
    fi
RUN test -f "/tmp/openvas-packages/${FINAL_PACKAGE_SET}.txt" \
    && apt-get update \
    && xargs -a "/tmp/openvas-packages/${FINAL_PACKAGE_SET}.txt" apt-get install --no-install-recommends --no-install-suggests -y \
    && rm -rf /var/lib/apt/lists/*

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
CMD ["/usr/local/bin/openvasd"]
