// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const KRB5_VERSION: &str = "1.20";
const KRB5_PATCH: &str = "1";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../../../misc/openvas-krb5.c");
    println!("cargo:rerun-if-changed=../../../../misc/openvas-krb5.h");
    println!("cargo::rerun-if-env-changed=TARGET");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();

    let extract_dir = fetch_krb5(&out_dir);
    build_krb5(&extract_dir.join("src"), &out_dir, &target);

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=krb5");
    println!("cargo:rustc-link-lib=static=k5crypto");
    println!("cargo:rustc-link-lib=static=com_err");
    println!("cargo:rustc-link-lib=static=gssapi_krb5");
    println!("cargo:rustc-link-lib=static=krb5support");

    println!("cargo:rustc-link-lib=resolv");

    let mut build = cc::Build::new();
    build
        .file("../../../../misc/openvas-krb5.c")
        .include(out_dir.join("include"))
        .opt_level(2);
    build.compile("openvas-krb5");

    let bindings = bindgen::Builder::default()
        .header("../../../../misc/openvas-krb5.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Unable to write bindings")
}

fn fetch_krb5(destination: &Path) -> PathBuf {
    let folder_name = format!("krb5-{}.{}", KRB5_VERSION, KRB5_PATCH);
    let extract_path = destination.join(&folder_name);
    let tar_path = extract_path.with_added_extension("tar.gz");

    if !extract_path.exists() {
        if !tar_path.exists() {
            let url = format!(
                "https://kerberos.org/dist/krb5/{}/{}.tar.gz",
                KRB5_VERSION, folder_name
            );

            Command::new("curl")
                .args(["--fail", "-L", "-O", &url])
                .current_dir(destination)
                .status()
                .unwrap();
        }

        Command::new("tar")
            .args(["-xzf", &tar_path.to_string_lossy()])
            .current_dir(destination)
            .status()
            .unwrap();
    }

    extract_path
}

fn build_krb5(src: &Path, install_prefix: &Path, target: &str) {
    if !Command::new("sh")
        .arg("-c")
        .arg(format!(
            r#"./configure --prefix={} \
            --enable-static \
            --disable-shared \
            --without-system-verto \
            --without-libedit  \
            --disable-rpath \
            --host={}"#,
            install_prefix.display(),
            target
        ))
        .current_dir(src)
        .status()
        .expect("Failed to run configure")
        .success()
    {
        panic!("Configure failed");
    }

    // Ignore status, as it make process might fail, but libs will still be built
    Command::new("make")
        .arg("-j")
        .current_dir(src)
        .status()
        .expect("failed to build krb5");

    Command::new("make")
        .arg("install")
        .current_dir(src)
        .status()
        .expect("failed to install krb5");
}
