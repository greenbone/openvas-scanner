# Manual Scan API Helpers

This directory contains helper targets for manually creating and controlling
scans against a running `openvasd` instance.

The automated smoketest suite is separate and lives in `smoketest/`.

## Purpose

Use `tests/Makefile` when you want to interact with the API manually during
development, for example to:

- create a scan from a JSON definition
- start or stop an existing scan
- inspect scan status or results
- remove a previously created scan

Use `tests/smoketest/` when you want the automated Hurl-based validation suite.

## Requirements

- running `openvasd` instance
- `make`
- `curl`
- `jq`
- client certificates in `../certs/clients/`

## Layout

- `smoketest/scans-user-flows/`: JSON scan definitions used by the helper targets
- `known-scans/`: local files containing scan IDs returned by the API

## Usage

Run these commands from `compose/tests/`.

### Create a scan

```bash
make create-<name>
```

This reads `smoketest/scans-user-flows/<name>.json`, creates the scan through
the API, and stores the returned scan ID in `known-scans/<name>`.

### Start a scan

```bash
make start-<name>
```

### Stop a scan

```bash
make stop-<name>
```

### Show status

```bash
make status-<name>
```

### Show results

```bash
make results-<name>
```

### Remove a scan

```bash
make rm-<name>
```

This deletes the scan through the API and removes the local ID file.

## Available Targets

Targets are generated from JSON files in `smoketest/scans-user-flows/`.

For each `<name>.json`, the following targets are available:

- `create-<name>`
- `start-<name>`
- `stop-<name>`
- `status-<name>`
- `results-<name>`
- `rm-<name>`

## Example

```bash
make create-victim-full-and-fast
make start-victim-full-and-fast
make status-victim-full-and-fast
make results-victim-full-and-fast
make rm-victim-full-and-fast
```

## Smoketests

Run the automated suite from `compose/` with:

```bash
make smoketest
```

Or run the Hurl suite directly with:

```bash
make -C smoketest
```
