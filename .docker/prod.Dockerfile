ARG VERSION=oldstable
# this allows to work on forked repository
ARG REPOSITORY=greenbone/openvas-scanner
FROM ${REPOSITORY}-build:$VERSION AS build
COPY . /source
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install 

FROM greenbone/gvm-libs:$VERSION

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    bison \
    libjson-glib-1.0-0 \
    libksba8 \
    nmap \
    libcap2-bin \
    snmp \
    netdiag \
    pnscan \
    rsync \
<<<<<<< HEAD
=======
    # net-tools is required by some nasl plugins.
    # nasl_pread: Failed to execute child process “netstat” (No such file or directory)
    net-tools \
    # for openvas-smb support
    python3-impacket \
    libgnutls30 \
    libgssapi3-heimdal \
    libkrb5-26-heimdal \
    libasn1-8-heimdal \
    libroken18-heimdal \
    libhdb9-heimdal \
    libpopt0 \
>>>>>>> 4e6ff767 (Fix: missing NASL dependency netstat)
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/ /
RUN ldconfig
# allow openvas to access raw sockets and all kind of network related tasks
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/sbin/openvas
