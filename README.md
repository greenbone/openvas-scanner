![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# OpenVAS

[![GitHub releases](https://img.shields.io/github/release/greenbone/openvas.svg)](https://github.com/greenbone/openvas/releases)
[![Code Documentation Coverage](https://img.shields.io/codecov/c/github/greenbone/openvas.svg?label=Doc%20Coverage&logo=codecov)](https://codecov.io/gh/greenbone/openvas)
[![Build and test](https://github.com/greenbone/openvas-scanner/actions/workflows/ci-c.yml/badge.svg?branch=main)](https://github.com/greenbone/openvas-scanner/actions/workflows/ci-c.yml?query=branch%3Amain++)

This is the Open Vulnerability Assessment Scanner (OpenVAS) of the
Greenbone Vulnerability Management (GVM) Solution.

It is used for the Greenbone Security Manager appliances and is a full-featured
scan engine that executes a continuously updated and extended feed of Network
Vulnerability Tests (NVTs).

## Releases
￼
All [release files](https://github.com/greenbone/openvas/releases) are signed with
the [Greenbone Community Feed integrity key](https://community.greenbone.net/t/gcf-managing-the-digital-signatures/101).
This gpg key can be downloaded at https://www.greenbone.net/GBCommunitySigningKey.asc
and the fingerprint is `8AE4 BE42 9B60 A59B 311C  2E73 9823 FAA6 0ED1 E580`.

## Installation

This module can be configured, built and installed with following commands:

    cmake .
    make install

For detailed installation requirements and instructions, please see the file
[INSTALL.md](INSTALL.md). The file also contains instructions for setting up
`openvas` and for making the scanner available to other GVM modules.

If you are not familiar or comfortable building from source code, we recommend
that you use the Greenbone Security Manager TRIAL (GSM TRIAL), a prepared virtual
machine with a readily available setup. Information regarding the virtual machine
is available at <https://www.greenbone.net/en/testnow>.

## Support

For any question on the usage of `openvas` please use the [Greenbone
Community Portal](https://community.greenbone.net/c/gse). If you found a problem
with the software, please [create an
issue](https://github.com/greenbone/openvas-scanner/issues) on GitHub. If you
are a Greenbone customer you may alternatively or additionally forward your
issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/openvas/pulls) on GitHub. Bigger
changes need to be discussed with the development team via the [issues section
at GitHub](https://github.com/greenbone/openvas/issues) first.

## License

This module is licensed under the [GNU General Public License v2.0
only](COPYING.GPLv2). Single files, however, are licensed either the GNU General
Public License v2.0 only or under GNU General Public License v2.0 or later,
please see the [COPYING](COPYING) file for details.
