# Docker Build Files

This directory contains the container build files and data used for OpenVAS scanner images.

## Files

- `prod.Dockerfile` builds all supported production-style image variants.
- `packages/` contains the runtime package lists selected by `VERSION`.

## Supported Variants

The single `prod.Dockerfile` is parameterized and is used for:

- stable
- oldstable
- testing

## Default Build

The default build produces the stable image variant.

Example:

```sh
podman build -f .docker/prod.Dockerfile .
```

## Important Build Arguments

### `VERSION`

Selects the image variant behavior.

Examples:

- `latest` for the stable build
- `oldstable` for the oldstable build
- `testing-edge` for the testing build

This value is used to derive:

- the base image tag for `gvm-libs` unless explicitly overridden
- the runtime package list from `.docker/packages/${VERSION}.txt`
- whether Debian apt suite aliases are rewritten to `VERSION_CODENAME`

Examples:

```sh
--build-arg VERSION=latest
--build-arg VERSION=oldstable
--build-arg VERSION=testing-edge
```

### `GVM_LIBS`

Overrides the `gvm-libs` repository.

Default:

```sh
ghcr.io/greenbone/gvm-libs
```

Example:

```sh
--build-arg GVM_LIBS=ghcr.io/greenbone/gvm-libs
```

### `BIN_VERSION`

Optional version string passed into the Rust build.

Example:

```sh
--build-arg BIN_VERSION=23.0.0
```

### `RUST_IMAGE`

Overrides the Rust builder image.

This is mainly needed for oldstable builds.

Example:

```sh
--build-arg RUST_IMAGE=rust:bookworm
```

### `OPENVAS_SMB_IMAGE`

Overrides the image used for the `openvas-smb` stage.

This is mainly needed for the testing build.

Example:

```sh
--build-arg OPENVAS_SMB_IMAGE=greenbone/openvas-smb:testing-edge
```

## Runtime Package Lists

Runtime packages are stored in separate files:

- `packages/latest.txt`
- `packages/oldstable.txt`
- `packages/testing-edge.txt`

This keeps package differences out of the Dockerfile.

## Build Examples

### Stable

```sh
podman build \
  -f .docker/prod.Dockerfile \
  --build-arg VERSION=latest \
  .
```

### Oldstable

```sh
podman build \
  -f .docker/prod.Dockerfile \
  --build-arg VERSION=oldstable \
  --build-arg RUST_IMAGE=rust:bookworm \
  .
```

### Testing

```sh
podman build \
  -f .docker/prod.Dockerfile \
  --build-arg VERSION=testing-edge \
  --build-arg OPENVAS_SMB_IMAGE=greenbone/openvas-smb:testing-edge \
  .
```
