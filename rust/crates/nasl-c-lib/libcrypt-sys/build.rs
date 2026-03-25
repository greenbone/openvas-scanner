// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

const GPG_ERROR_VERSION: &str = "1.54";
const LIBGCRYPT_VERSION: &str = "1.10.2";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c/gcrypt_error.c");
    println!("cargo:rerun-if-changed=c/gcrypt_error.h");
    println!("cargo:rerun-if-changed=c/gcrypt_mac.c");
    println!("cargo:rerun-if-changed=c/gcrypt_mac.h");
    println!("cargo::rerun-if-env-changed=TARGET");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();

    let path = fetch_source("libgpg-error", GPG_ERROR_VERSION, &out_dir);
    build_autotools_project(&path, &target);

    let path = fetch_source("libgcrypt", LIBGCRYPT_VERSION, &out_dir);
    build_autotools_project(&path, &target);

    let include_dir = out_dir.join("include");
    let lib_dir = out_dir.join("lib");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=gcrypt");
    println!("cargo:rustc-link-lib=static=gpg-error");

    cc::Build::new()
        .file("c/gcrypt_mac.c")
        .file("c/gcrypt_error.c")
        .include(include_dir)
        .opt_level(2)
        .compile("crypt");
}

fn fetch_source(name: &str, version: &str, destination: &Path) -> PathBuf {
    let folder_name = format!("{}-{}", name, version);
    let extract_path = destination.join(&folder_name);
    let tar_path = extract_path.with_added_extension("tar.bz2");

    if !extract_path.exists() {
        if !tar_path.exists() {
            let url = format!("https://gnupg.org/ftp/gcrypt/{name}/{folder_name}.tar.bz2");

            Command::new("curl")
                .args(["--fail", "-O", &url])
                .current_dir(destination)
                .status()
                .unwrap();
        }

        Command::new("tar")
            .args(["-xf", &tar_path.to_string_lossy()])
            .current_dir(destination)
            .status()
            .unwrap();
    }

    extract_path
}

fn build_autotools_project(src: &Path, target: &str) -> PathBuf {
    let mut config = autotools::Config::new(src);
    config
        .enable_static()
        .disable_shared()
        .config_option("with-pic", None)
        .host(target);

    config.build()
}
