# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

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
