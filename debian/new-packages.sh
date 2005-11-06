#!/bin/sh

MIRROR=http://ftp.gwdg.de/pub/linux/misc/nessus/

if [ -n "$1" ] 
then
	VERSION=$1
else
	echo "Usage: $0 nessus_version"
	exit 1
fi


DOWNLOAD=$MIRROR/nessus-$VERSION/src
[ ! -f "MD5.$VERSION" ] && wget -nv -nH -nd -O MD5.$VERSION $DOWNLOAD/MD5
#gpg --verify-files MD5.$VERSION
#if [ $? -ne 0 ] 
#then
#   echo "Error verifying the signature, please check"
#   exit 1
#fi

for package in libnasl nessus-core nessus-libraries nessus-plugins-GPL; do
	if [ ! -f ${package}_${VERSION}.orig.tar.gz ]
	then 
		wget -nv -nH -nd  $DOWNLOAD/${package}-${VERSION}.tar.gz
		if [ $? -ne 0 ] 
		then
			echo "Error downloading $package, please check"
			exit 1
		fi
		md5=`md5sum  ${package}-${VERSION}.tar.gz |cut -f 1 -d " "`
		grep $md5 MD5.$VERSION | grep $package 2>&1 >/dev/null
		if [ $? -ne 0 ] 
		then
			echo "Md5sum not found, please check"
			exit 1
		fi

		mv ${package}-${VERSION}.tar.gz ${package}_${VERSION}.orig.tar.gz
	fi
done

# Adjust
mv nessus-plugins-GPL-${VERSION}.tar.gz nessus-plugins_${VERSION}.orig.tar.gz

CURDIR=`pwd`
for file in *$VERSION*tar.gz; do 
echo "Decompressing $file"
tar -zxf $file
[ $? -ne 0 ] && {
	echo "Error decompressing $file"
	exit 1
}
done

date=`date +%D | sed -e 's/\//-/g'`
patchlog="patch-$date.txt"
[ -f "$patchlog" ] && rm -f $patchlog

for package in nessus-libraries nessus-core libnasl nessus-plugins; do 
	if [ -d $package ] ; then
	mv $package $package-$VERSION
	newpatch=`ls --sort=t $package*diff.gz 2>/dev/null|head -1` 
	if [ -n "$newpatch" ] && [ -e "$newpatch" ] ; then
		cd $package-$VERSION 
		echo "Applying patch from $newpatch to $package-$VERSION"
		echo "Applying patch from $newpatch to $package-$VERSION" >>../$patchlog
		zcat ../$newpatch  | patch -p1 >> ../$patchlog 2>&1
		[ $? -ne 0 ] && echo "Error applying patch from $newpatch please check $patchlog"
		chmod a+x debian/rules
		dch -v $VERSION-1  "New upstream release"
		cd $CURDIR
	fi
	fi
done


# Compilation order:
# 1.- libnessus 
# 2.- libnasl
# 3.- nessus-plugins (depends 1)
# 4.- nessus-core (depends 1-2)

