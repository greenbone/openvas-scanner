# OpenVAS Scanner Compose

This directory contains compose files and helper targets for running
`openvasd` locally with Docker or Podman.

## Files

- `base.yaml`: base service definition with HTTP enabled
- `tls.yaml`: adds TLS
- `mtls.yaml`: adds mutual TLS
- `local-registry.yaml`: local registry services used by the compose test setup
- `tests/victim.yaml`: extra services used by the compose test setup
- `Makefile`: helper targets for certificates, local startup, and smoketests

## Requirements

- `docker compose`, `docker-compose`, or `podman-compose`
- `make`
- for mTLS and smoketests: `curl`, `jq`, `hurl`

## Certificates

The TLS and mTLS setups use certificates from `certs/` by default.

If you do not have local certificates yet, generate the development ones with:

```bash
make
```

This creates:

- `certs/server.pem`
- `certs/server.key`
- `certs/clients/client1.pem`
- `certs/clients/client1.key`

## Running The Stack

Start the base HTTP setup:

```bash
podman-compose -f base.yaml up
```

Start with TLS:

```bash
podman-compose -f base.yaml -f tls.yaml up
```

Start with mTLS:

```bash
podman-compose -f base.yaml -f mtls.yaml up
```

When mTLS is enabled, client requests must include the client key and certificate:

```bash
curl -vk \
  --key certs/clients/client1.key \
  --cert certs/clients/client1.pem \
  https://localhost:3000/scans
```

## Makefile Targets

The main helper targets are:

- `make test-environment-up`: start the compose test environment
- `make test-environment-running`: start the compose test environment and wait for services
- `make local-test-environment-up`: build the local image and start the compose test environment
- `make local-test-environment-running`: build the local image, start it, and wait for services
- `make test-environment-down`: stop the compose test environment and remove volumes
- `make smoketest`: build the local image, wait for services, and run the Hurl smoketest suite
- `make smoketests`: alias for `make smoketest`

## Smoketests

Run the full local smoketest flow with:

```bash
make smoketest
```

That target:

1. builds the local `openvas` image
2. starts the compose test environment
3. waits until `openvasd` is running and the registry seed job finished
4. runs the Hurl tests from `tests/smoketest`

If the environment is already running, you can run the Hurl suite directly with:

```bash
make -C tests/smoketest
```

## Tests Directory Layout

- `tests/smoketest/`: automated Hurl-based smoketests
- `tests/Makefile`: manual helper targets for creating, starting, stopping, querying, and removing scans via the API

`tests/Makefile` is still useful if you want interactive scan lifecycle helpers while developing. If you no longer use those manual targets, deleting that file would be reasonable. I would keep the Hurl suite in `tests/smoketest/` rather than flattening it into `tests/`.

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `OPENVAS_IMAGE` | `ghcr.io/greenbone/openvas-scanner:stable` | Image used by `test-environment-up` |
| `OPENVASD_EXTERNAL_BIND_ADDRESS` | `127.0.0.1:3000` | Host bind address |
| `OPENVAS_LOG_LEVEL` | `64` | Numeric log level for OpenVAS |
| `OPENVAS_REDIS_MEMORY_LIMIT` | `0` | Redis memory limit |
| `OPENVAS_REDIS_MEMORY_RESERVATION` | `0` | Redis memory reservation hint |
| `OPENVAS_REDIS_RESTART_CONDITION` | `on-failure` | Redis restart policy |
| `OPENVASD_MEMORY_LIMIT` | `0` | `openvasd` memory limit |
| `OPENVASD_MEMORY_RESERVATION` | `0` | `openvasd` memory reservation hint |
| `OPENVASD_RESTART_CONDITION` | `on-failure` | `openvasd` restart policy |
