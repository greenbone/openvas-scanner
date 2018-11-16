![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# OpenVAS Scanner

[![GitHub releases](https://img.shields.io/github/release/greenbone/openvas-scanner.svg)](https://github.com/greenbone/openvas-scanner/releases)
[![Code Documentation Coverage](https://codecov.io/gh/greenbone/openvas-scanner/branch/master/graphs/badge.svg?flag=documentation)](https://codecov.io/gh/greenbone/openvas-scanner)`(Documentation Coverage)`
[![CircleCI](https://circleci.com/gh/greenbone/openvas-scanner/tree/master.svg?style=svg)](https://circleci.com/gh/greenbone/openvas-scanner/tree/master)

This is the Open Vulnerability Assessment System (OpenVAS) Scanner of the
Greenbone Vulnerability Management (GVM) Solution.

It is used for the Greenbone Security Manager appliances and is a full-featured
scan engine that executes a continuously updated and extended feed of Network
Vulnerability Tests (NVTs).

## Installation

This module can be configured, built and installed with following commands:

    cmake .
    make install

For detailed installation requirements and instructions, please see the file
[INSTALL.md](INSTALL.md). The file also contains instructions for setting up
`openvas-scanner` and for making the scanner available to other GVM modules.

If you are not familiar or comfortable building from source code, we recommend
that you use the Greenbone Community Edition, a prepared virtual machine with a
readily available setup. Information regarding the virtual machine is available
at <https://www.greenbone.net/en/community-edition/>.

## Support

For any question on the usage of `openvas-scanner` please use the [Greenbone
Community Portal](https://community.greenbone.net/c/gse). If you found a problem
with the software, please [create an
issue](https://github.com/greenbone/openvas-scanner/issues) on GitHub. If you
are a Greenbone customer you may alternatively or additionally forward your
issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/openvas-scanner/pulls) on GitHub. Bigger
changes need to be discussed with the development team via the [issues section
at GitHub](https://github.com/greenbone/openvas-scanner/issues) first.

## License

This module is licensed under the [GNU General Public License v2.0
only](COPYING.GPLv2). Single files, however, are licensed either the GNU General
Public License v2.0 only or under GNU General Public License v2.0 or later,
please see the [COPYING](COPYING) file for details.
