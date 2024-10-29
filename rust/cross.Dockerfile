ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE
RUN apt-get update && apt-get install -y \
  bison \
  flex \
  curl \
  zlib1g-dev
RUN curl -Lfo /tmp/pcap.tar.gz https://www.tcpdump.org/release/libpcap-1.10.3.tar.gz
WORKDIR /tmp
RUN tar xvf pcap.tar.gz
RUN ls -las
WORKDIR /tmp/libpcap-1.10.3
ENV CHOST=amd64
ENV CC=x86_64-linux-gnu-gcc
ENV CFLAGS='-Os'
RUN ./configure --host=x86_64-unknown-linux-gnu --with-pcap=linux
RUN cat config.log
RUN make install

RUN mkdir /tmp/zlib
RUN curl -sf -L https://www.zlib.net/current/zlib.tar.gz | tar zxvf - --strip-components=1 -C /tmp/zlib
WORKDIR /tmp/zlib
RUN ./configure
RUN make install
RUN ldconfig

RUN curl -Lfo /tmp/openssl.tar.gz https://www.openssl.org/source/old/1.1.1/openssl-1.1.1.tar.gz
WORKDIR /tmp
RUN tar xvf openssl.tar.gz
RUN ls -las
WORKDIR /tmp/openssl-1.1.1
RUN ./Configure linux-x86_64 --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
ENV LD_LIBRARY_PATH=/usr/local/ssl/lib:${LD_LIBRARY_PATH}
RUN ldconfig
RUN make install
ENV PKG_CONFIG_PATH=/usr/local/ssl/lib/pkgconfig:${PKG_CONFIG_PATH}
