#!/bin/sh

version="$1"
type="$2"

# Split version string into fields
IFS='.' read -r field1 field2 field3 << EOF
$version
EOF

# On major enhance major version, set minor and patch to 0
# On minor enhance minor version, set patch to 0
# On patch enhance patch version
case "$type" in
  "major")
    field1=$(expr $field1 + 1)
    field2=0
    field3=0
    ;;
  "minor")
    field2=$(expr $field2 + 1)
    field3=0
    ;;
  "patch")
    field3=$(expr $field3 + 1)
    ;;
  *)
    echo "Error: Invalid update type '$type'" >&2
    return 1
    ;;
esac

new_version="$field1.$field2.$field3"
echo "$new_version"
