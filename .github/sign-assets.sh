#!/bin/bash

set -e

# use own gpg_home to not intefere with other settings
tmp=
trap 'rm -rf "$tmp"' EXIT INT TERM HUP
tmp=$(mktemp -d)
export GNUPGHOME="$tmp"
# enable gpg to work in container environments:
# https://d.sb/2016/11/gpg-inappropriate-ioctl-for-device-errors
printf "use-agent\npinentry-mode loopback" > $GNUPGHOME/gpg.conf
printf "allow-loopback-pinentry" > $GNUPGHOME/gpg-agent.conf
echo RELOADAGENT | gpg-connect-agent
# store password, we need it multiple times
read -s password
# store to file
mv "$1" "$GNUPGHOME/private.pgp"
# import and gather key id
key_id=$(echo "$password" | \
  gpg --import --batch --armor --passphrase-fd 0 $GNUPGHOME/private.pgp 2>&1 | \
  grep "key [A-Z0-9]*:" | \
  head -n 1 | \
  sed 's/.*key \([A-Z0-9]*\):.*/\1/')
  echo "key_id: $key_id"

# Create a signed ASC for each file in the assets directory
for file in assets/*; do
  if [ -f "$file" ]; then
    echo $password | gpg --default-key $key_id --batch --passphrase-fd 0 --clear-sign --detach-sign "$file"
  fi
done

