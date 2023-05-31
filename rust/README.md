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

- nasl-cli
- openvasd

You have to execute
```
cargo build --release
```

To enable the experimental features:

```
cargo build -F experimental --release
```

# Architecture Overview

The architecture is a layered architecture to make it easy to extend or modify it.

This is done by providing specialized crates by task and abstraction of data base technologies and business logic.

It roughly follows the pattern of:

![overview picture](doc/overview.svg?raw=true "Overview")

## Contribution

If you are unsure how to start or want to discuss an improvement or feature feel free to create an issue.

Feel invited to create a draft PR and open a discussions about a new feature, improvements or even architectural changes if you want to discuss based on concrete examples.

If you want to help we are very happy about:

- built in functions implementations
- documentation improvements

Additionally we want to:

- do improvements in the built in function handling as we want to be more modular
- clean up the storage interface as it is very misleading currently because it enforced implementations of retrieve and dispatch.
- extend `nasl-cli` with a `openvas-nasl` like functionality so that we can test scripts
- implement multithreading of interpreter
- implement scheduling for a multi script run
- create an http frontend based on [OpenAPI definition](./doc/openapi.yml)

## Current status

This is an very early status and not yet in a stable condition.
