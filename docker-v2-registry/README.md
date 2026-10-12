# Docker Registry V2 subrepository fixture

This fixture runs the official `registry:2` image and seeds it through the Docker Registry HTTP API V2. It uses anonymous HTTP access, matching a default local Distribution registry rather than Harbor's additional API.

The Registry API does not model a subrepository as its own object. For the target

```text
oci://127.0.0.1:55000/openvas-subrepository
```

the scanner first receives `404 NAME_UNKNOWN` from `/v2/openvas-subrepository/tags/list`, then has to list `/v2/_catalog` and select repository names below that prefix. The fixture contains:

- `openvas-subrepository/image-a:latest`
- `openvas-subrepository/image-a:v1`
- `openvas-subrepository/nested/image-b:latest`

Run the live integration test from this directory:

```bash
./test.bash
```

The script starts and seeds the registry, then runs the ignored Rust integration test. It leaves the registry running for inspection:

```bash
curl -i http://127.0.0.1:55000/v2/
curl http://127.0.0.1:55000/v2/_catalog
curl http://127.0.0.1:55000/v2/openvas-subrepository/image-a/tags/list
```

Stop it with:

```bash
./down.bash
```

Set `OPENVAS_DOCKER_V2_PORT` to use a port other than `55000`. The scripts require Podman, curl, GNU tar, gzip, and sha256sum.
