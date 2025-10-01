# to be built with openvas-scanner top level dir as base

FROM registry.community.greenbone.net/community/gvm-libs:edge

# Build from src
COPY . /opt/openvas-build/
WORKDIR /opt/openvas-build

RUN .github/install-openvas-dependencies.sh

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    redis-server \
    redis-tools \
    patchelf

RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install

COPY rust/openvasd-tests/entrypoint.sh /entrypoint.sh

COPY .docker/openvas.conf /etc/openvas/

RUN chmod +x /entrypoint.sh

RUN sed 's/redis-openvas/redis/g' /opt/openvas-build/config/redis-openvas.conf > /etc/redis/redis.conf

EXPOSE 3000

ENTRYPOINT ["/entrypoint.sh"]
