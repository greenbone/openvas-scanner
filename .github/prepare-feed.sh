#!/bin/sh
# This script prepares the feed used for integration tests.
# We don't use the download action because it is not capapble of a fork based
# workflow.
[ -z $FEED_DIR ] && FEED_DIR="/var/lib/openvas/plugins"
DOCKER_CMD=docker
FEED_IMAGE="greenbone/vulnerability-tests"
set -e
printf "Copying feed $FEED_IMAGE "
FEED_VERSION=$($DOCKER_CMD run --rm $FEED_IMAGE sh -c 'ls /var/lib/openvas/' | sort -r | head -n 1)
printf "(version: $FEED_VERSION) to $FEED_DIR\n"
# instanciate container
CFP="/var/lib/openvas/$FEED_VERSION/vt-data/nasl/"
CID=$($DOCKER_CMD create $FEED_IMAGE)
rm -rf $FEED_DIR
mkdir -p $FEED_DIR
$DOCKER_CMD cp $CID:$CFP $FEED_DIR
mv $FEED_DIR/nasl/* $FEED_DIR
rm -r $FEED_DIR/nasl
$DOCKER_CMD rm $CID
