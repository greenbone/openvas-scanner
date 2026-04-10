# OpenVASD Scan Makefile

This Makefile provides a simple interface to manage scans via the
OpenVASD HTTP API.

It uses JSON scan definitions and stores created scan IDs locally to
allow follow-up actions.

## Requirements

- running OpenVASD instance
- `make`
- `curl`
- `jq`

## Structure

- `smoketest/scans-user-flows/`
  - JSON scan definitions

- `known-scans/`
  - stores scan IDs after creation

## Usage

### Create scans

Creates a scan from a JSON definition and stores its ID:

```bash
make create-<name>
```

### Start scans
```bash
make start-<name>
```
### Stop scans

```bash
make stop-<name>
```
### Get scan status
```bash
make status-<name>
```
### Get scan results
```bash
make results-<name>
```

### Remove scans

Deletes the scan and removes the stored ID:

```bash
make rm-<name>
```

### Available Targets

Targets are derived from JSON files in:

`smoketest/scans-user-flows/`

For each file:

`<name>.json`

the following targets are available:
- create-<name>
- start-<name>
- stop-<name>
- status-<name>
- results-<name>
- rm-<name>
#### Example

```bash
make create-victim-full-and-fast
make start-victim-full-and-fast
make status-victim-full-and-fast
make results-victim-full-and-fast
make rm-victim-full-and-fast
```
