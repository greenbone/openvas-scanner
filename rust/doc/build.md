# Building the Rust Binaries

This document explains how to build the Rust binaries with the static archives required by the build scripts.

## Required Build Tools

The Rust build itself still needs the normal build-time packages.

## Environment Variables

The Rust build scripts support two styles of configuration.

### Bundle-style configuration

This is the setup used in `.docker/prod.Dockerfile`.

Variables:

- `OPENVAS_ARCHIVES`
- `LIBPCAP_LIBDIR`

Meaning:

- `OPENVAS_ARCHIVES` points to a flat directory containing the required static archives and an `include/` subdirectory.
- `LIBPCAP_LIBDIR` points to the directory containing `libpcap.a`.

The build scripts emit the required native linker search paths automatically from the resolved archive locations.

Expected bundle layout:

```text
archives/
├── libgcrypt.a
├── libgpg-error.a
├── libpcap.a
├── libgssapi_krb5.a
├── libkrb5.a
├── libk5crypto.a
├── libcom_err.a
├── libkrb5support.a
└── include/
    ├── gcrypt.h
    ├── gpg-error.h
    ├── pcap.h
    ├── krb5.h
    ├── com_err.h
    ├── profile.h
    ├── gssapi/
    └── krb5/
```

### Direct configuration without a bundle directory

Instead of `OPENVAS_ARCHIVES`, the build scripts also accept dedicated variables for the two custom static dependencies.

Variables:

- `OPENVAS_GCRYPT_ARCHIVES`
- `OPENVAS_GCRYPT_INCLUDE_DIR`
- `OPENVAS_KRB5_ARCHIVES`
- `OPENVAS_KRB5_INCLUDE_DIR`
- `LIBPCAP_LIBDIR`

Meaning:

- `OPENVAS_GCRYPT_ARCHIVES` is a path list containing `libgcrypt.a` and `libgpg-error.a`.
- `OPENVAS_GCRYPT_INCLUDE_DIR` points to the directory containing `gcrypt.h` and `gpg-error.h`.
- `OPENVAS_KRB5_ARCHIVES` is a path list containing:
  - `libgssapi_krb5.a`
  - `libkrb5.a`
  - `libk5crypto.a`
  - `libcom_err.a`
  - `libkrb5support.a`
- `OPENVAS_KRB5_INCLUDE_DIR` points to the directory containing:
  - `krb5.h`
  - `gssapi/gssapi.h`
  - `gssapi/gssapi_krb5.h`
- `LIBPCAP_LIBDIR` points to the directory containing `libpcap.a`.

The build scripts emit the required native linker search paths automatically from the resolved archive locations.

Note:

- `OPENVAS_GCRYPT_ARCHIVES` and `OPENVAS_KRB5_ARCHIVES` are path lists.
- Use your platform's normal path separator.
- On Linux, that means `:`.

## Example 0: Use the default archive bundle directory

This is the default local workflow and the one used by CI.

From the repository root:

```sh
cd rust
make
cargo build --release
```

Or explicitly through the crate-local Makefile:

```sh
cd rust
make -C crates/nasl-c-lib
cargo build --release
```

What `make` does:

- builds the `build-archives` stage from `.docker/prod.Dockerfile`
- copies `/archives` from the container image to `crates/nasl-c-lib/build-cache/archives`
- uses `docker` if available
- otherwise uses `podman`
- uses `distrobox-host-exec` automatically when running inside distrobox

No extra environment variables are required for this setup. The build scripts in `crates/nasl-c-lib` automatically look for the default bundle directory at:

```text
crates/nasl-c-lib/build-cache/archives
```

Use this approach unless you specifically want to manage archive locations yourself.

## Example 1: Use an explicit archive bundle directory

This example shows the same bundle-based setup as example 0, but with `OPENVAS_ARCHIVES` and `LIBPCAP_LIBDIR` set explicitly.

To keep the example self-contained, the archive bundle is populated from the container build stage.

```sh
mkdir -p rust/crates/nasl-c-lib/build-cache/archives

podman build \
  --target build-archives \
  -f .docker/prod.Dockerfile \
  -t openvas-build-archives \
  .

container_id=$(podman create openvas-build-archives)
podman cp "$container_id":/archives/. rust/crates/nasl-c-lib/build-cache/archives/
podman rm "$container_id"
```

Then build the Rust binaries:

```sh
cd rust
export OPENVAS_ARCHIVES="$PWD/crates/nasl-c-lib/build-cache/archives"
export LIBPCAP_LIBDIR="$PWD/crates/nasl-c-lib/build-cache/archives"
cargo build --release
```


## Example 2: Build Without a Bundle Directory

If you do not want to use `OPENVAS_ARCHIVES`, set the archive and include variables directly.

This example assumes:

- `libpcap.a` is in `$HOME/openvas-static/libpcap`
- gcrypt archives are in `$HOME/openvas-static/gcrypt/lib`
- gcrypt headers are in `$HOME/openvas-static/gcrypt/include`
- krb5 archives are in `$HOME/openvas-static/krb5/lib`
- krb5 headers are in `$HOME/openvas-static/krb5/include`

Example:

```sh
cd rust

export OPENVAS_GCRYPT_ARCHIVES="$HOME/openvas-static/gcrypt/lib/libgcrypt.a:$HOME/openvas-static/gcrypt/lib/libgpg-error.a"
export OPENVAS_GCRYPT_INCLUDE_DIR="$HOME/openvas-static/gcrypt/include"

export OPENVAS_KRB5_ARCHIVES="$HOME/openvas-static/krb5/lib/libgssapi_krb5.a:$HOME/openvas-static/krb5/lib/libkrb5.a:$HOME/openvas-static/krb5/lib/libk5crypto.a:$HOME/openvas-static/krb5/lib/libcom_err.a:$HOME/openvas-static/krb5/lib/libkrb5support.a"
export OPENVAS_KRB5_INCLUDE_DIR="$HOME/openvas-static/krb5/include"

export LIBPCAP_LIBDIR="$HOME/openvas-static/libpcap"

cargo build --release
```

In this setup:

- `OPENVAS_ARCHIVES` is not used
- the gcrypt build script gets explicit archive and include paths
- the krb5 build script gets explicit archive and include paths
- `libpcap` is found through `LIBPCAP_LIBDIR`
- the build scripts emit all required linker search paths from the resolved archive locations

## Summary

For most users, use example 0:

- run `make` in `rust/`
- let the default archive bundle be generated in `crates/nasl-c-lib/build-cache/archives`
- run `cargo build --release`

Use example 1 if you want to point the build explicitly at a bundle directory, and use example 2 only if you already manage the required static archives and headers yourself.
