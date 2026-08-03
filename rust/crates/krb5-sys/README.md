# openvas-krb5-sys

This crate owns the native Kerberos dependency used by the Rust scanner. It
contains the MIT Kerberos 1.22.2 release sources and exposes Rust bindings for
the OpenVAS Kerberos C shim.

`build.rs` performs an out-of-tree static build under Cargo's `OUT_DIR`. It
configures only the MIT Kerberos library directories needed by the scanner,
installs their archives and public headers into `OUT_DIR`, compiles the shim,
and emits the corresponding Cargo linker directives. It does not download
sources, use Docker, or require a system Kerberos installation.

The native build needs a POSIX shell, `make`, a C compiler and archiver for the
Cargo target, Perl, awk, and the usual bindgen/libclang build dependency. The
checked-in release sources already contain `configure` and generated parser
sources, so Autoconf and Bison are not needed.

The vendored MIT Kerberos distribution retains its upstream `NOTICE` file at
`vendor/krb5-1.22.2/NOTICE`.

To refresh the checked-in release sources, run `make vendor` in this directory.
This maintenance target downloads the configured upstream release; normal Cargo
builds never access the network.
