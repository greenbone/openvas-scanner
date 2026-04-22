// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[path = "../build_support.rs"]
mod build_support;

use build_support::ArchiveConfig;

const ARCHIVES_DIR_ENV: &str = "OPENVAS_ARCHIVES";
const GCRYPT_ARCHIVES_ENV: &str = "OPENVAS_GCRYPT_ARCHIVES";
const GCRYPT_INCLUDE_DIR_ENV: &str = "OPENVAS_GCRYPT_INCLUDE_DIR";

const GCRYPT_ARCHIVES: &[&str] = &["libgcrypt.a", "libgpg-error.a"];
const GCRYPT_HEADERS: &[&str] = &["gcrypt.h", "gpg-error.h"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c/gcrypt_error.c");
    println!("cargo:rerun-if-changed=c/gcrypt_error.h");
    println!("cargo:rerun-if-changed=c/gcrypt_mac.c");
    println!("cargo:rerun-if-changed=c/gcrypt_mac.h");
    println!("cargo:rerun-if-env-changed=TARGET");
    let archive_config = ArchiveConfig {
        bundle_env: ARCHIVES_DIR_ENV,
        archives_env: GCRYPT_ARCHIVES_ENV,
        include_env: GCRYPT_INCLUDE_DIR_ENV,
        bundled_archives: GCRYPT_ARCHIVES,
    };
    archive_config.emit_rerun_if_env_changed();

    let resolved = archive_config.resolve();
    resolved.assert_archives_present(GCRYPT_ARCHIVES_ENV, GCRYPT_ARCHIVES);
    resolved.assert_headers_present(GCRYPT_INCLUDE_DIR_ENV, GCRYPT_HEADERS);
    resolved.emit_link_directives();

    cc::Build::new()
        .file("c/gcrypt_mac.c")
        .file("c/gcrypt_error.c")
        .include(&resolved.include_dir)
        .opt_level(2)
        .compile("crypt");
}
