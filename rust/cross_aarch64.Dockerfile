FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:latest
# it is based on xenial and therefore doesn't have
# libpcap-dev available as a install candidate for aarach64.
# The edge version (as written in 2023-03-08) is based on 
# 20.4 and would have a candidate ready; however the build time
# is very bad on edge therefore we wait until it is stable.
RUN apt-get update && apt-get install -y \
  bison \
  flex \
  curl
RUN curl -o /tmp/pcap.tar.gz https://www.tcpdump.org/release/libpcap-1.10.3.tar.gz
WORKDIR /tmp
RUN tar xvf pcap.tar.gz
RUN ls -las
WORKDIR /tmp/libpcap-1.10.3
ENV CC=aarch64-linux-gnu-gcc
ENV CFLAGS='-Os'
RUN ./configure --host=aarch64-unknown-linux-gnu --with-pcap=linux
RUN cat config.log
RUN make install
