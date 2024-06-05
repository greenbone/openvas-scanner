ARG VERSION=edge

FROM greenbone/gvm-libs:$VERSION
LABEL deprecated="This image is deprecated and may be removed soon."

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
  bison \
  build-essential \
  clang \
  clang-format \
  clang-tools \
  cmake \
  lcov \
  libgnutls28-dev \
  libgpgme-dev \
  libjson-glib-dev \
  libksba-dev \
  libpaho-mqtt-dev \
  libpcap-dev \
  zlib1g-dev \
  libssh-gcrypt-dev \
  libbsd-dev \
  # for linking openvas-smb (libopenvas_wmiclient)
  libgnutls30 \
  libgssapi3-heimdal \
  libkrb5-26-heimdal \
  libasn1-8-heimdal \
  libroken19-heimdal \
  libhdb9-heimdal \
  libpopt0 \
  libcurl4-gnutls-dev \
  && rm -rf /var/lib/apt/lists/*
