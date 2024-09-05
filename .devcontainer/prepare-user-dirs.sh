#!/bin/sh
# This scripts creates the dirs defined in dirs and sets the rights to the given user and id.
# This script creates a user with a $UID as well as a group with $GID 
# afterwards it creates set of directories, assigns ownership to a newly created user and group, and configures sudo permissions for the user.
# This is done to allow cmake --build build --target install to work without permission issues.

dirs="
/workspaces
/run/gvm
/var/log/gvm
/etc/openvas
/var/lib/openvas
/usr/local/lib
/usr/local/share/man/man1/
/usr/local/share/man/man8/
/usr/local/include/gvm
/usr/local/share/openvas
/usr/local/bin
/usr/local/sbin
/var/lib/openvas
/var/lib/notus
/var/lib/gvm
/var/lib/openvasd
/etc/openvasd
/run/redis
"

set -ex
groupadd --gid "$GID" "developer" || true
# for the case that the GID already existed when we tried to create developer
# this can happen when we reuse staff from a mac os host
group_name=$(getent group "$GID" | cut -d: -f1) 

useradd --uid "$UID" --gid "$group_name" --shell /bin/bash --groups redis --create-home user

for dir in ${dirs[@]}; do
	if [ ! -d $dir ]; then
		mkdir -p $dir
	fi
	chown -R user:$group_name $dir
done
# allow user to run sudo without password since it is intented as development 
# container it is assumed that the user wants to install or manipulate the container
echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/user
