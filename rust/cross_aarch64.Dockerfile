FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:latest
# it is based on xenial and therefore doesn't have
# libpcap-dev available as a install candidate for aarach64.
# The edge version (as written in 2023-03-08) is based on
# 20.4 and would have a candidate ready; however the build time
# is very bad on edge therefore we wait until it is stable.
RUN apt-get update && apt-get install -y \
  bison \
  flex \
  curl \
  zlib1g-dev
RUN curl -o /tmp/pcap.tar.gz https://www.tcpdump.org/release/libpcap-1.10.3.tar.gz
ENV CC=aarch64-linux-gnu-gcc
ENV CFLAGS='-Os'
ENV CHOST=arm64

WORKDIR /tmp
RUN tar xvf pcap.tar.gz
RUN ls -las
WORKDIR /tmp/libpcap-1.10.3
RUN ./configure --host=aarch64-unknown-linux-gnu --with-pcap=linux
RUN cat config.log
RUN make install

RUN mkdir /tmp/zlib
RUN curl -sf -L https://www.zlib.net/current/zlib.tar.gz | tar zxvf - --strip-components=1 -C /tmp/zlib
WORKDIR /tmp/zlib
RUN ./configure
RUN make install
RUN ldconfig

RUN curl -o /tmp/openssl.tar.gz https://www.openssl.org/source/old/1.1.1/openssl-1.1.1.tar.gz
WORKDIR /tmp
RUN tar xvf openssl.tar.gz
RUN ls -las
WORKDIR /tmp/openssl-1.1.1
RUN ./Configure linux-aarch64 --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
ENV LD_LIBRARY_PATH=/usr/local/ssl/lib:${LD_LIBRARY_PATH}
RUN ldconfig
RUN make install
ENV PKG_CONFIG_PATH=/usr/local/ssl/lib/pkgconfig:${PKG_CONFIG_PATH}
