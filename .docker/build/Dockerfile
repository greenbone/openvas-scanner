# Dockerfile for openvas-scanner-$VERSION-$COMPILER-build

# Define ARG we use through the build
ARG VERSION=master
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

FROM greenbone/openvas-scanner-$VERSION-$COMPILER-testing

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

COPY . /usr/local/src/openvas-scanner
WORKDIR /usr/local/src

# clone and install openvas-scanner
 RUN cd openvas-scanner && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make install