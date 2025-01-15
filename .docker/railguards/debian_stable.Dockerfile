# This Dockerfile is not meant to be actually used, it is meant for testing
# the integrity when building:
# - gvm-libs
# - openvas-smb
# - openvas-scanner
#
# together from a main branch.
#
# If it builds without error everything is as expected.
FROM debian:stable
# CLONE gvm-libs
# CLONE openvas-smb
# Install dependencies
# check ld
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

