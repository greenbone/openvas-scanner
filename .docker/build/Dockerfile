ARG VERSION=master
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
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_MODULE_PATH=/usr/lib/x86_64-linux-gnu/cmake/ .. && \
    make install
