#! /bin/sh

# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Run the signature verification tests and
#              print a summary of the tests.
#
# Authors:
# Bernhard Herzog <bernhard.herzog@intevation.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

export OPENVAS_GPGHOME=gnupg
NASL=../openvas-nasl

signed_file=signed.nasl
signed_file_sig=signed.nasl.asc

numok=0
numfailed=0

# USAGE: check_script SCRIPTNAME EXPECTED-RESULT
#
# Runs SCRIPTNAME and compares its stdout with EXPECTED-RESULT.  If
# they're equal, the test has passed. otherwise the test failed.
check_script() {
    echo -n "$1 "
    result=$($NASL $1 2> $1.err.log)
    if [ "x$result" = "x$2" ]; then
	numok=$((numok + 1))
	echo OK
    else
	numfailed=$((numfailed + 1))
	echo FAILED
    fi
}

# a signed script
check_script $signed_file YES

# an unsigned script.  No output is generated because the nasl
# interpreter will not even attempt to execute the file
unsigned=temp-unsigned.nasl
cp $signed_file $unsigned
check_script $unsigned ""

# an invalid signature. No output is generated because the nasl
# interpreter will not even attempt to execute the file
badsig=temp-badsig.nasl
cp $signed_file $badsig
cp $signed_file_sig $badsig.asc
echo "# modified" >> temp-badsig.nasl
check_script $badsig ""


# print summary
echo "-------------------------------"
echo "$((numok + numfailed)) tests, $numok ok, $numfailed failed"

# exit with non-zero status if any test has failed
if [ $numfailed -gt 0 ]; then
    exit 1
fi
