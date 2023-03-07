ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE
RUN apt-get update && apt-get install -y \
  libpcap-dev
