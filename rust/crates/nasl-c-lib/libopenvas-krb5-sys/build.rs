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

    let target = env::var("TARGET").unwrap();

    // Try to find static Kerberos libraries via pkg-config
    let build_path = build_krb5_from_source(&target);

    // Link against the built static libraries
    println!(
        "cargo:rustc-link-search=native={}",
        build_path.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=krb5");
    println!("cargo:rustc-link-lib=static=k5crypto");
    println!("cargo:rustc-link-lib=static=com_err");
    println!("cargo:rustc-link-lib=static=gssapi_krb5");
    println!("cargo:rustc-link-lib=static=krb5support");

    // Link system dependencies
    println!("cargo:rustc-link-lib=keyutils");
    println!("cargo:rustc-link-lib=resolv");

    let mut build = cc::Build::new();
    build
        .file("../../../../misc/openvas-krb5.c")
        .include(build_path.join("include"))
        .opt_level(2);

    build.compile("openvas-krb5");

    let bindings = bindgen::Builder::default()
        .header("../../../../misc/openvas-krb5.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings")
}

fn build_krb5_from_source(target: &str) -> PathBuf {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let install_dir = out_dir.join("krb5-build");

    let extract_dir = fetch_krb5(&out_dir);

    build_krb5(&extract_dir.join("src"), &install_dir, target);

    install_dir
}

fn fetch_krb5(destination: &Path) -> PathBuf {
    let folder_name = format!("krb5-{}.{}", KRB5_VERSION, KRB5_PATCH);
    let extract_path = destination.join(&folder_name);

    // Check if already downloaded and extracted
    if extract_path.join("src/configure").exists() {
        println!("cargo:warning=Kerberos source already downloaded, skipping");
        return extract_path;
    }

    let tar_path = extract_path.with_added_extension("tar.gz");

    let url = format!(
        "https://kerberos.org/dist/krb5/{}/{}.tar.gz",
        KRB5_VERSION, folder_name
    );

    Command::new("curl")
        .args(["--fail", "-L", "-O", &url])
        .current_dir(destination)
        .status()
        .unwrap();

    Command::new("tar")
        .args(["-xzf", &tar_path.to_string_lossy()])
        .current_dir(destination)
        .status()
        .unwrap();

    extract_path
}

fn build_krb5(src: &Path, install_prefix: &Path, target: &str) {
    // Configure with prefix pointing to install location
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "./configure --prefix={} --enable-static --disable-shared --without-system-verto --without-libedit --disable-rpath --host={}",
            install_prefix.display(),
            target
        ))
        .current_dir(src)
        .status()
        .expect("Failed to run configure");

    if !status.success() {
        panic!("Configure failed");
    }

    // Build everything (this may fail on utilities but libraries will build)
    let _ = Command::new("make").arg("-j").current_dir(src).status();

    // Install what was built successfully
    let _ = Command::new("make")
        .arg("install")
        .current_dir(src)
        .status();
}
