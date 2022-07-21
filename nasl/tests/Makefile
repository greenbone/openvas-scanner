# Copyright (C) 2009-2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

# Testsuite for the NASL interpreter
# Makefile to run the testsuite

TEST_SCRIPTS = test_bn.nasl test_md.nasl test_dh.nasl test_blowfish.nasl \
               test_dsa.nasl test_privkey.nasl test_rsa.nasl test_hexstr.nasl \
	       test_isotime.nasl test_crypt_data_aes.nasl

ifndef OPENVAS_NASL
	OPENVAS_NASL := openvas-nasl
endif
.PHONY: check

all: check

# Scripts which are useful for debugging.  Eventually they should be
# enhanced so that they can be run as part of the regression test.
debug_scripts =

check: testsuiterun.nasl
	${OPENVAS_NASL} -X testsuiterun.nasl

testsuiterun.nasl: $(TEST_SCRIPTS) testsuiteinit.nasl testsuitesummary.nasl
	cat testsuiteinit.nasl $(TEST_SCRIPTS) testsuitesummary.nasl > testsuiterun.nasl
