#!/usr/bin/env bash

set -euo pipefail

version="${1:-}"
type="${2:-}"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Error: Invalid release version '$version'" >&2
  exit 1
fi

IFS='.' read -r field1 field2 field3 <<< "$version"

case "$type" in
  "major")
    field1=$((field1 + 1))
    field2=0
    field3=0
    ;;
  "minor")
    field2=$((field2 + 1))
    field3=0
    ;;
  "patch")
    field3=$((field3 + 1))
    ;;
  *)
    echo "Error: Invalid update type '$type'" >&2
    exit 1
    ;;
esac

new_version="$field1.$field2.$field3"
echo "$new_version"
