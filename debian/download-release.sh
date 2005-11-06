#!/bin/sh
# Useful script to download all the orig.tar.gz files of 
# a given Nessus release
#
# (c) 2003 Javier Fernandez-Sanguino

RELEASE=$1

[ -z "$RELEASE" ] && {
	echo "Tell me which release! (ie. 2.0.1, 1.2.3...)"
	exit 1
}

FILES="libnasl nessus-core nessus-libraries nessus-plugins"
# URL should be one of the available
#at http://www.nessus.org/nessus_2_0.html
URL="http://ftp.gwdg.de/pub/linux/misc/nessus"

for file in $FILES; do
 wget -O ${file}_${RELEASE}.orig.tar.gz $URL/nessus-$RELEASE/src/$file-$RELEASE.tar.gz
done

wget -O MD5sums_$RELEASE.txt $URL/nessus-$RELEASE/src/MD5


