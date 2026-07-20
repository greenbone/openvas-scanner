# Manual Scan API Helpers

This directory contains helper targets for manually creating and controlling
scans against a running `openvasd` instance.

## Purpose

Use `tests/Makefile` when you want to interact with the API manually during
development, for example to:

- create a scan from a JSON definition
- start or stop an existing scan
- inspect scan status or results
- remove a previously created scan

## Requirements

- running `openvasd` instance
- `make`
- `curl`
- `jq`
- client certificates in `../certs/clients/`

## Usage

Run these commands from `compose/tests/`.

### Create a scan

```bash
make create-<name>
```

This reads `../../rust/data/tests/scanner/scans/<name>.json`, creates the scan through
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

Targets are generated from JSON files in `../../rust/data/tests/scanner/scans/`.

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
