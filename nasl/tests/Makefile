# Testsuite for the NASL interpreter
# Makefile to run the testsuite

TEST_SCRIPTS = test_bn.nasl test_md.nasl test_dh.nasl test_blowfish.nasl \
               test_dsa.nasl test_privkey.nasl test_rsa.nasl test_hexstr.nasl \
	       test_isotime.nasl

# Scripts which are useful for debugging.  Eventually they should be
# enhanced so that they can be run as part of the regression test.
debug_scripts =

KEYRING_FILES = gnupg/pubring.gpg gnupg/secring.gpg gnupg/trustdb.gpg

check: testsuite $(KEYRING_FILES)
	../openvas-nasl -X testsuite
	@echo
	./test_script_signing.sh

testsuite: $(TEST_SCRIPTS) testsuiteinit.nasl testsuitesummary.nasl
	cat testsuiteinit.nasl $(TEST_SCRIPTS) testsuitesummary.nasl > testsuite


$(KEYRING_FILES): keys/keypair.asc keys/ownertrust.txt
	mkdir gnupg
	chmod 700 gnupg
	gpg --homedir=gnupg --import keys/keypair.asc
	gpg --homedir=gnupg --import-ownertrust keys/ownertrust.txt
