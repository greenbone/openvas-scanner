# Rust Scanner implementation

This is the rust scanner implementation with the goal to replace the current scanner stack
(openvas-scanner, ospd-openvas, notus-scanner), including the Open Scanner Protocol (OSP). The rust implementation of the new [HTTP scanner API](https://greenbone.github.io/scanner-api/) is called
**openvasd**. It provides an interface to manage scans for vulnerability testing. It currently utilizes the **openvas-scanner** to perform tasks.

This project also consist of a collection of tools called [**scannerctl**](scannerctl/README.md). It contains variety of utilities for different tasks. For more information look into [**scannerctl**](scannerctl/README.md).


# Implementation of the NASL Attack Scripting Language

The goal is to have rust based implementation of NASL.

NASL is a domain-specific language (DSL) used by OpenVAS Scanner to write vulnerability tests and other security checks.

The decision to rewrite certain parts in rust was mainly to have an easier way to maintain it in the future the decision for rust is based on the interoperability between rust and c source code so that we can integrate our rust code in openvas and vice versa when it is required to do so.

The implementation is split into multiple parts that are reflected in the directory layout.


# Requirements

- rust toolchain

Additionally for the features defined as experimental you need:

- libpcap
- openssl
- pkg-config
- zlib

# Build

To build and create the executables

- scannerctl
- openvasd

You have to execute
```
cargo build --release
```

To enable the experimental features:

```
cargo build -F experimental --release
```

# Contribution

If you are unsure how to start or want to discuss an improvement or feature feel free to create an issue.

Feel invited to create a draft PR and open a discussions about a new feature, improvements or even architectural changes if you want to discuss based on concrete examples.

If you want to help we are very happy about:

- built in functions implementations
- documentation improvements

Additionally we want to:

- do improvements in the built in function handling as we want to be more modular
- clean up the storage interface as it is very misleading currently because it enforced implementations of retrieve and dispatch.
- extend `scannerctl` with a `openvas-nasl` like functionality so that we can test scripts
- implement multithreading of interpreter
- implement scheduling for a multi script run
- create an http frontend based on [OpenAPI definition](./doc/openapi.yml)

# Current status

The programs openvasd and scannerctl are usable, but might not support all features yet. The current openvasd implementation does not use and internal rust scanner yet, but still uses the c implementation of the openvas-scanner. Additionally depending on the configuration, an ospd-openvas instance is also needed.
