// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[path = "../build_support.rs"]
mod build_support;

use std::env;
use std::path::PathBuf;

use build_support::ArchiveConfig;

const ARCHIVES_DIR_ENV: &str = "OPENVAS_ARCHIVES";
const KRB5_ARCHIVES_ENV: &str = "OPENVAS_KRB5_ARCHIVES";
const KRB5_INCLUDE_DIR_ENV: &str = "OPENVAS_KRB5_INCLUDE_DIR";

const KRB5_ARCHIVES: &[&str] = &[
    "libgssapi_krb5.a",
    "libkrb5.a",
    "libk5crypto.a",
    "libcom_err.a",
    "libkrb5support.a",
];
const KRB5_HEADERS: &[&str] = &["krb5.h", "gssapi/gssapi.h", "gssapi/gssapi_krb5.h"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../../../misc/openvas-krb5.c");
    println!("cargo:rerun-if-changed=../../../../misc/openvas-krb5.h");
    println!("cargo:rerun-if-env-changed=TARGET");
    let archive_config = ArchiveConfig {
        bundle_env: ARCHIVES_DIR_ENV,
        archives_env: KRB5_ARCHIVES_ENV,
        include_env: KRB5_INCLUDE_DIR_ENV,
        bundled_archives: KRB5_ARCHIVES,
    };
    archive_config.emit_rerun_if_env_changed();

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let resolved = archive_config.resolve();
    resolved.assert_archives_present(KRB5_ARCHIVES_ENV, KRB5_ARCHIVES);
    resolved.assert_headers_present(KRB5_INCLUDE_DIR_ENV, KRB5_HEADERS);
    resolved.emit_link_directives();

    println!("cargo:rustc-link-lib=resolv");

    let mut build = cc::Build::new();
    build
        .file("../../../../misc/openvas-krb5.c")
        .include(&resolved.include_dir)
        .opt_level(2);
    build.compile("openvas-krb5");

    let bindings = bindgen::Builder::default()
        .header("../../../../misc/openvas-krb5.h")
        .clang_arg(format!("-I{}", resolved.include_dir.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Unable to write bindings")
}
