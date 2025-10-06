# to be built with openvas-scanner top level dir as base

FROM registry.community.greenbone.net/community/gvm-libs:edge

# Copy all the files we need for openvas. We do this
# explicitly here to avoid copying the rust folder
# which would invalidate the cache if there are any changes
# to the openvasd code.
COPY .github/ /opt/openvas-build/.github/
COPY CMakeLists.txt /opt/openvas-build/
COPY cmake/ /opt/openvas-build/cmake/
COPY src/ /opt/openvas-build/src/
COPY .docker/ /opt/openvas-build/.docker/
COPY config/ /opt/openvas-build/config/
COPY doc/ /opt/openvas-build/doc/
COPY nasl/ /opt/openvas-build/nasl/
COPY misc/ /opt/openvas-build/misc/
COPY VERSION.in /opt/openvas-build/
COPY COPYING /opt/openvas-build/
COPY README.md /opt/openvas-build/

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
