ARG VERSION=unstable
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
    libbsd0 \
    rsync \
    && rm -rf /var/lib/apt/lists/*

COPY .docker/openvas.conf /etc/openvas/
COPY --from=build /install/ /

RUN ldconfig
# allow openvas to access raw sockets and all kind of network related tasks
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/sbin/openvas
