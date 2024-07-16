# This script creates a sha256sums over the nasl and inc files within this dir.
#!/bin/sh
PWD=$(pwd)
set -e
find . -type f -regex ".*\.\(nasl\|inc\)\$"  -exec sha256sum {} \; | tee sha256sums
