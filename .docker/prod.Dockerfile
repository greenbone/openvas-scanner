ARG VERSION=edge
# this allows to work on forked repository
ARG REPOSITORY=greenbone/openvas-scanner

FROM greenbone/openvas-smb AS openvas-smb

FROM greenbone/gvm-libs:$VERSION AS build
COPY . /source
RUN sh /source/.github/install-openvas-dependencies.sh
COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
RUN cmake -DCMAKE_BUILD_TYPE=Release -DINSTALL_OLD_SYNC_SCRIPT=OFF -B/build /source
RUN DESTDIR=/install cmake --build /build -- install

FROM greenbone/gvm-libs:$VERSION
ARG TARGETPLATFORM
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
  bison \
  libglib2.0-0 \
  libjson-glib-1.0-0 \
  libksba8 \
  nmap \
  libcap2-bin \
  snmp \
  netdiag \
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
  libcurl3-gnutls \
  zlib1g \
  libhiredis0.14 \
  && rm -rf /var/lib/apt/lists/*
COPY .docker/openvas.conf /etc/openvas/
# must be pre built within the rust dir and moved to the bin dir
# usually this image is created within in a ci ensuring that the
# binary is available.
COPY assets/$TARGETPLATFORM/scannerctl /usr/local/bin/scannerctl
COPY assets/$TARGETPLATFORM/openvasd /usr/local/bin/openvasd
RUN chmod +x /usr/local/bin/scannerctl
RUN chmod +x /usr/local/bin/openvasd
COPY --from=build /install/ /
COPY --from=openvas-smb /usr/local/lib/ /usr/local/lib/
COPY --from=openvas-smb /usr/local/bin/ /usr/local/bin/
RUN ldconfig
# allow openvas to access raw sockets and all kind of network related tasks
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/sbin/openvas
# allow nmap to send e.g. UDP or TCP SYN probes without root permissions
ENV NMAP_PRIVILEGED=1
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
CMD /usr/local/bin/openvasd

