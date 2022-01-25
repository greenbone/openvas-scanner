Copyright (C) 2022 Greenbone Networks GmbH

SPDX-License-Identifier: GPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

