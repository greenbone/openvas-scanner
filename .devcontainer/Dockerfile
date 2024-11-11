FROM rust:latest
ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install -y \
    sudo \ 
    git \ 
    rsync \ 
    pipx \ 
    redis-server \ 
    clangd \
    # Runtime dependencies, required for .devcontainer
    nmap \
    snmp \
    netdiag \
    pnscan \
    # net-tools is required by some nasl plugins.
    # nasl_pread: Failed to execute child process “netstat” (No such file or directory)
    net-tools 
# Add prepare-user-dirs.sh and execcute it
COPY prepare-user-dirs.sh /prepare-user-dirs.sh
COPY build-cmake-project.sh /usr/local/bin/build-cmake-project.sh
RUN chmod +x /usr/local/bin/build-cmake-project.sh
COPY build-openvas /usr/local/bin/build-openvas
RUN chmod +x /usr/local/bin/build-openvas
COPY build-gvm-libs /usr/local/bin/build-gvm-libs
RUN chmod +x /usr/local/bin/build-gvm-libs
COPY github-clone.sh /usr/local/bin/github-clone
RUN chmod +x /usr/local/bin/github-clone

RUN bash /prepare-user-dirs.sh && rm /prepare-user-dirs.sh
USER user
RUN python3 -m pipx install greenbone-feed-sync
# installing gvm-libs and openvas-scanner
RUN github-clone greenbone/gvm-libs 
RUN github-clone greenbone/openvas-scanner
RUN sudo sh /workspaces/greenbone/gvm-libs/.github/install-dependencies.sh
RUN sudo sh /workspaces/greenbone/openvas-scanner/.github/install-openvas-dependencies.sh

RUN build-gvm-libs
RUN build-openvas
# Currently we don't install scannerctl and openvasd as they don't have dependencies
# that must be preloaded in order to function.
# WORKDIR /workspaces/openvas/rust/scannerctl 
# RUN cargo install --path .
# WORKDIR /workspaces/openvas/rust/openvasd
# RUN cargo install --path .
USER redis
RUN sed 's/redis-openvas/redis/' /workspaces/greenbone/openvas-scanner/config/redis-openvas.conf | tee /etc/redis/redis.conf
USER user
# We clean up the cloned repositories as they are usually mounted into the container
RUN rm -r /workspaces/greenbone


# RUN sudo apt-get clean && sudo rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]

RUN rustup component add rust-analyzer rust-src
ENV PATH="/home/user/.cargo/bin:${PATH}"
ENV PATH="/home/user/.local/bin:${PATH}"
RUN echo "alias start_redis='redis-server /etc/redis/redis.conf'" >> /home/user/.bashrc
ENV start_redis="redis-server /etc/redis/redis.conf"
WORKDIR /workspaces
CMD ["/bin/bash"]
