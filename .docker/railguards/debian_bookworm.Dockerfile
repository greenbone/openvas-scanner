# This Dockerfile is not meant to be actually used, it is meant for testing
# the integrity when building:
# - gvm-libs
# - openvas-smb
# - openvas-scanner
#
# together from a main branch.
#
# If it builds without error everything is as expected.


# this is needed when we just want to copy the build binaries onto our dest dir
FROM debian:bookworm AS rs-binaries
COPY . /source
RUN mv /source/.docker/install /install || true

FROM debian:bookworm
COPY . /source
RUN apt update && apt install -y git
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

COPY --from=rs-binaries /install/usr/local/bin/openvasd /usr/local/bin/openvasd
COPY --from=rs-binaries /install/usr/local/bin/scannerctl /usr/local/bin/scannerctl
RUN chmod 755 /usr/local/bin/scannerctl
RUN chmod 755 /usr/local/bin/openvasd
RUN ls -las /usr/local/bin/
