# nasl-c-lib

Contains C functions, structures, and Rust wrappers used by NASL builtin functions.

This library uses the Rust `cc` crate to compile C code with the system C compiler.

Some parts of the C implementation require external static libraries. Those archives and headers are generated into `build-cache/archives` by the crate-local `Makefile`, using the `build-archives` stage from `../../../.docker/prod.Dockerfile`.

The generated archive bundle matches the build setup described in [`doc/build.md`](../../doc/build.md), especially the bundle-style configuration using:

- `OPENVAS_ARCHIVES`
- `LIBPCAP_LIBDIR`

The build scripts emit the required linker search paths automatically from the resolved archive locations.

## Preparing the build cache

From the repository root:

```sh
make
```

Or from this crate directory:

```sh
make
```

The Makefile will:
- use `docker` if available
- otherwise use `podman` if available
- use `distrobox-host-exec` automatically when running inside distrobox

This generates the required static archives and headers in:

```text
crates/nasl-c-lib/build-cache/archives
```

The resulting bundle layout is the one expected by the Rust build scripts from `doc/build.md`, including archives such as:

- `libgcrypt.a`
- `libgpg-error.a`
- `libpcap.a`
- `libgssapi_krb5.a`
- `libkrb5.a`
- `libk5crypto.a`
- `libcom_err.a`
- `libkrb5support.a`
- headers in `include/`

If you want to build manually without the Makefile, or if you need the direct non-bundle environment-variable setup, see [`doc/build.md`](../../doc/build.md).

To remove the generated cache:

```sh
make clean
```

## Add new C functions

1. Create a new `.c` and `.h` file in the `c` directory. Please use or create an appropriate sub-directory.
2. Configure `build.rs`
   1. Add `.file("c/your/code.c")` to the `cc` builder.
   2. Add `println!("cargo:rerun-if-changed=c/your/header.h");`.
   3. Add additional required external libraries with `println!("cargo:rustc-link-lib=static=your_lib");`. The library must be built before with a `libyourlib-sys` crate. See `libcrypt-sys` for reference.
3. Write a wrapper
   1. Create a Rust file in the `src` directory. Please use or create an appropriate sub-directory.
   2. Write the binding within `extern "C"`.
   3. Write a public wrapper function that can be used by other libraries.

## Additional notes

- The `println!` macro is used to set flags for the Rust compiler.
- The external C libraries are prepared through build scripts and the generated build cache.
