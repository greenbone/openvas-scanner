FROM registry.community.greenbone.net/community/vulnerability-tests AS plugins

FROM registry.community.greenbone.net/community/notus-data AS notus
RUN tar -xvf /var/lib/notus/notus-data.tar.gz -C /var/lib/notus
RUN rm /var/lib/notus/notus-data.tar.gz

# rust latest is based on debian:latest
FROM rust:latest AS rust
# TODO: move building to another step so that it doesn't has to build each time
# CLONE gvm-libs
# CLONE openvas-smb
# Install dependencies
# check ld
COPY --from=plugins /var/lib/openvas/22.04/vt-data/nasl /var/lib/openvas/plugins
COPY --from=notus /var/lib/notus /var/lib/notus
COPY . /source
RUN apt update && apt install -y git redis-server
# for more logging
RUN bash /source/.devcontainer/github-clone.sh greenbone/gvm-libs
RUN bash /source/.devcontainer/github-clone.sh greenbone/openvas-smb
# tests implicitely if there are dependencies conflicts
RUN sh /workspaces/greenbone/gvm-libs/.github/install-dependencies.sh
RUN sh /workspaces/greenbone/openvas-smb/.github/install-openvas-smb-dependencies.sh
RUN sh /source/.github/install-openvas-dependencies.sh
# build everything
RUN sh /source/.devcontainer/build-cmake-project.sh /workspaces/greenbone/gvm-libs
RUN sh /source/.devcontainer/build-cmake-project.sh /workspaces/greenbone/openvas-smb
RUN sh /source/.devcontainer/build-cmake-project.sh /source
# TODO: setup user dirs and openvas user for openvasd
RUN mkdir /etc/openvasd
COPY .docker/e2e/gvmd/openvasd.toml /etc/openvasd/openvasd.toml
WORKDIR /source/rust/examples/tls/self-signed
RUN make server client
RUN mkdir /etc/openvasd/tls
RUN mkdir -p /var/lib/openvasd/tls
RUN mv server.rsa /var/lib/openvasd/tls/server.rsa
RUN mv server.pem /etc/openvasd/tls/server.pem
RUN mkdir /etc/openvasd/tls/client
RUN cp client.pem /etc/openvasd/tls/client/client1.pem
RUN mv client.* /workspaces/
RUN mkdir /run/redis
RUN chown redis:redis /run/redis
RUN sed 's/redis-openvas/redis/' /source/config/redis-openvas.conf | tee /etc/redis/redis.conf
WORKDIR /source/rust
RUN cargo build --release
RUN cp target/release/openvasd /usr/local/bin/
RUN cp target/release/scannerctl /usr/local/bin/
# gvmd - stuff
# pg-gvm
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libglib2.0-dev \
    libgnutls28-dev \
    postgresql-server-dev-all \
    pkg-config \
    libical-dev && \
    rm -rf /var/lib/apt/lists/*
RUN bash /source/.devcontainer/github-clone.sh greenbone/pg-gvm
RUN sh /source/.devcontainer/build-cmake-project.sh /workspaces/greenbone/pg-gvm

RUN bash /source/.devcontainer/github-clone.sh nichtsfrei/gvmd
# We don't care about code quality
# RUN sed -i 's/-Werror //g' /workspaces/nichtsfrei/gvmd/CMakeLists.txt
RUN sh /workspaces/nichtsfrei/gvmd/.github/install-dependencies.sh
RUN sh /source/.devcontainer/build-cmake-project.sh /workspaces/nichtsfrei/gvmd "-DOPENVASD=1 -DCMAKE_BUILD_TYPE=Release"
# System user gvmd
#TODO set GID and UID via build env
RUN apt-get install -y postgresql pipx
RUN addgroup --gid 1001 --system gvmd && \
    adduser --no-create-home --shell /usr/bin/bash --disabled-password --uid 1001 --system --group gvmd
RUN addgroup --system openvas && \
    adduser --no-create-home --shell /usr/bin/bash --disabled-password --system --group openvas
RUN chown -R openvas:openvas /etc/openvasd && \
    chown -R openvas:openvas /var/lib/openvasd
RUN install -m 755 /source/.docker/e2e/gvmd/start-gvmd.sh /usr/local/bin/start-gvmd
RUN install -m 755 /workspaces/greenbone/pg-gvm/.docker/start-postgresql.sh /usr/local/bin/start-postgresql
#  args: ["sed 's/mqtt_server_uri = .*/openvasd_server = https:\\/\\/localhost:443/' /etc/openvas/openvas.conf > /mnt/ovc/openvas.conf; cp /etc/openvas/openvas_log.conf /mnt/ovc/"]          ;
# RUN sed -i 's/mqtt_server_uri = .*/openvasd_server = http:\\/\\/localhost:3000/' /etc/openvas/openvas.conf
RUN mkdir -p /run/gvmd && \
    mkdir -p /var/lib/gvm && \
    mkdir -p /var/log/gvm && \
    chown -R gvmd:gvmd /etc/gvm && \
    chown -R gvmd:gvmd /run/gvmd && \
    chown -R gvmd:gvmd /var/lib/gvm && \
    chown -R gvmd:gvmd /var/log/gvm && \
    chown gvmd:gvmd /workspaces/client.rsa
RUN cp -r /source/.docker/e2e/gvmd/service /etc/service
RUN find /etc/service -type f -name "run" -exec chmod +x {} \;
# USER gvmd
RUN python3 -m pipx install gvm-tools
USER root
# service management
RUN apt-get install -y runit
CMD ["runsvdir", "/etc/service"]
