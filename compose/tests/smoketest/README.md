# OpenVASD Smoketest

This directory contains smoketests for validating a running OpenVASD
instance via its HTTP API.

Tests are executed via `make` and implemented using Hurl.

## Requirements

- running OpenVASD instance
- `make`
- `hurl`

## Configuration

The following variables can be overridden:

```bash
OPENVASD_SERVER=https://127.0.0.1:3000
CLIENT_KEY=../../client-keys/client1.key
CLIENT_CERT=../../client-certs/client1.pem
```

## Usage

Run the default smoketest suite:

```bash
make
```

This runs:

```bash
make up-and-running
make notus
make scans-user-flow-victim-simple-auth-ssh
```

### Available Targets

```bash

# Basic checks
make up-and-running
make notus
make scans
# User flow targets are derived from JSON files in scans-user-flows/.
make scans-user-flow-victim-simple-auth-ssh
# those take longer
make scans-user-flow-victim-discovery
make scans-user-flow-victim-full-and-fast
```

