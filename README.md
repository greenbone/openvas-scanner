![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# OpenVAS Scanner

[![GitHub releases](https://img.shields.io/github/release/greenbone/openvas-scanner.svg)](https://github.com/greenbone/openvas-scanner/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/greenbone/openvas-scanner.svg)](https://hub.docker.com/r/greenbone/openvas-scanner/)
[![Docker Image Size](https://img.shields.io/docker/image-size/greenbone/openvas-scanner.svg?maxAge=2592000)](https://hub.docker.com/r/greenbone/openvas-scanner/)
[![CI](https://github.com/greenbone/openvas-scanner/actions/workflows/control.yml/badge.svg?branch=main)](https://github.com/greenbone/openvas-scanner/actions/workflows/control.yml?query=branch%3Amain)

This is the OpenVAS Scanner of the Greenbone Community Edition.

It is used for the Greenbone Enterprise appliances and is a full-featured
scan engine that executes a continuously updated and extended feed of
Vulnerability Tests (VTs).

## Releases

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
that you use the Greenbone Enterprise TRIAL, a prepared virtual
machine with a readily available setup. Information regarding the virtual machine
is available at <https://www.greenbone.net/en/testnow>.

## Rust Implementation

This repository also consists of a [rust project](rust/README.md) aiming to replace the current scanner stack
(openvas-scanner, ospd-openvas, notus-scanner). It simplifies the use of the scanner and centralizes
everything needed for scanning. Currently it uses the openvas-scanner as scan engine.

## Docker, [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/)

If you want to use the docker files provided in this repository you can pull them 
from [here](https://hub.docker.com/r/greenbone/openvas-scanner). You can also locally 
build them using:
```
docker build -t <image-name> -f .docker/prod.Dockerfile .
```
For more information about building docker images, see 
[official man](https://docs.docker.com/engine/reference/commandline/build/).
We also provide a [fully containerized 
solution](https://greenbone.github.io/docs/latest/22.4/container/)
for the Greenbone Community Edition.

> Please beware: The Greenbone Community Container are currently under development.

## Support

For any question on the usage of `openvas` please use the [Greenbone
Community Portal](https://community.greenbone.net/). If you found a problem
with the software, please [create an
issue](https://github.com/greenbone/openvas-scanner/issues) on GitHub. If you
are a Greenbone customer you may alternatively or additionally forward your
issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone AG](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/openvas-scanner/pulls) on GitHub.
Remember to commit the contribution agreement as explained in [RELICENSING](https://github.com/greenbone/openvas-scanner/tree/main/RELICENSE) folder with your first PR.
Bigger changes should be discussed with the development team via the [issues section at GitHub](https://github.com/greenbone/openvas-scanner/issues) first.

## License

This repository consists of two scanner implementation, one in programming language C and one in programming language Rust.

This module except for the Rust-implementation in directory rust/ is licensed under the GNU General Public License v2.0 only. Single files, however, are licensed either under the GNU General Public License v2.0 only or under GNU General Public License v2.0 or later, please see the [license-details.md](license-details.md) file for details.

The Rust-implementation in directory rust/ is licensed under the GNU General Public License v2.0 or later with OpenSSL exception. Single files, however, are additionally licensed under MIT.

