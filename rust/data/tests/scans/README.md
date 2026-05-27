# OpenVAS compatibility scan fixtures

This directory contains fixtures for comparing openvasd scan output against
references generated with the classic OpenVAS scanner.

Layout:

- `scans/<name>/scan.json`: scan config submitted to openvasd.
- `scans/<name>/*.nasl`, `*.inc`: minimal feed files used by that scan.
- `snapshots/<name>/snapshot.json`: raw reference generated from OpenVAS.

Generate snapshots with the compose helper:

```sh
make -C compose openvas-compat-snapshots
```

This requires `curl`, `hurl`, `jq`, and a working Docker/Podman compose setup.

or directly with:

```sh
./rust/data/tests/scans/generate-openvas-snapshots.sh
```

or for one case:

```sh
./rust/data/tests/scans/generate-openvas-snapshots.sh report-functions
```

The generator reuses the existing compose smoketest environment
(`compose/Makefile`'s `local-test-environment-running` target by default),
injects each fixture feed into the running `openvasd` container, loads the
fixture metadata into the OpenVAS Redis cache, and runs the scan through the
public mTLS API. The only generated reference file is `snapshot.json`, containing
`scan_id`, final `status`, and `results`. No separate local OpenVAS setup is
needed.

Run the count-based openvasd compatibility smoketest with:

```sh
make -C compose openvas-compat
```

That target starts the compose environment with `SCANNER_TYPE=openvasd`, injects
the same fixture feed, runs each scan via Hurl, and asserts that the number of
results matches the OpenVAS snapshot.
