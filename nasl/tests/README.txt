Notes for the OpenVAS-NASL Test-Suite
=====================================


Signature tests
---------------

The test suite comes with a keypair used to create and check signatures
for testing.  In SVN the keys and trustdb are managed in plain text
files in the keys subdirectory.  Running the testsuite creates the gnupg
subdirectory which contains the keys and trustdb in the form used by
GnuPG.  Summary of the key currently in use:

   pub   1024D/D23A2818 2007-10-04
   uid                  OpenVAS Testsuite Key (only used for tests)
   sub   2048g/0FF68D39 2007-10-04

Passphrase is "openvas" (without the quotes).


Common commands
~~~~~~~~~~~~~~~

Here are the most important commands that one may need when hacking on
the test-suite (all commands assume the working directory is the test
directory):

1. Signing a file

   gpg --homedir=gnupg --detach-sign -a somescript.nasl

This will create the signature in the file somescript.nasl.asc


2. Recreating/updating the files in the keys subdirectory

Exporting the keypair:

  gpg --homedir=gnupg --export-secret-key -a -o keys/keypair.asc D23A2818

Exporting the trustdb:

  gpg --homedir=gnupg-orig/ --export-ownertrust > keys/ownertrust.txt

