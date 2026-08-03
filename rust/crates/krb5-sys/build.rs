// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const KRB5_SOURCE: &str = "vendor/krb5-1.22.2/src";
const OPENVAS_KRB5_SOURCE: &str = "../../../misc/openvas-krb5.c";
const OPENVAS_KRB5_HEADER: &str = "../../../misc/openvas-krb5.h";
const KRB5_BUILD_DIRS: &[&str] = &[
    "util/support",
    "util/et",
    "util/profile",
    "include",
    "lib/crypto",
    "lib/krb5",
    "lib/gssapi",
];
const KRB5_LIBRARIES: &[&str] = &["gssapi_krb5", "krb5", "k5crypto", "com_err", "krb5support"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={KRB5_SOURCE}");
    println!("cargo:rerun-if-changed={OPENVAS_KRB5_SOURCE}");
    println!("cargo:rerun-if-changed={OPENVAS_KRB5_HEADER}");
    println!("cargo:rerun-if-env-changed=MAKE");

    let manifest_dir = required_path("CARGO_MANIFEST_DIR");
    let out_dir = required_path("OUT_DIR");
    let source_dir = manifest_dir.join(KRB5_SOURCE);
    let build_dir = out_dir.join("krb5-build");
    let install_dir = out_dir.join("krb5-install");

    recreate_directory(&build_dir, "Kerberos build");
    recreate_directory(&install_dir, "Kerberos install");

    configure_krb5(&source_dir, &build_dir, &install_dir);
    build_and_install_krb5(&build_dir);
    assert_krb5_install(&install_dir);
    compile_openvas_shim(&manifest_dir, &install_dir);
    emit_link_directives(&install_dir);
    generate_bindings(&manifest_dir, &install_dir, &out_dir);
}

fn configure_krb5(source_dir: &Path, build_dir: &Path, install_dir: &Path) {
    let target = required_var("TARGET");
    let host = required_var("HOST");
    let compiler = cc::Build::new()
        .target(&target)
        .host(&host)
        .opt_level_str(&required_var("OPT_LEVEL"))
        .warnings(false)
        .get_compiler();
    let archiver = cc::Build::new().target(&target).host(&host).get_archiver();

    let mut configure = Command::new(source_dir.join("configure"));
    configure
        .current_dir(build_dir)
        .arg(format!("--prefix={}", install_dir.display()))
        .args([
            "--enable-static",
            "--disable-shared",
            "--disable-nls",
            "--without-system-verto",
            "--without-libedit",
            "--disable-rpath",
            "--with-crypto-impl=builtin",
        ])
        .env("CC", compiler.path())
        .env("CFLAGS", join_command_args(compiler.args()))
        .env("AR", archiver.get_program())
        .envs(compiler.env().iter().cloned())
        // None of the Kerberos libraries selected below contains C++ code.
        .env("CXX", "false");

    if target != host {
        configure.arg(format!("--host={target}"));
    }

    run(&mut configure, "configure vendored MIT Kerberos");
}

fn build_and_install_krb5(build_dir: &Path) {
    for directory in KRB5_BUILD_DIRS {
        let mut make = make_command(build_dir);
        make.args(["-C", directory]);
        run(&mut make, &format!("build Kerberos directory {directory}"));
    }

    let mut make = make_command(build_dir);
    make.arg("install-mkdirs");
    run(&mut make, "create the Kerberos install directories");

    for directory in KRB5_BUILD_DIRS {
        let mut make = make_command(build_dir);
        make.args(["-C", directory, "install"]);
        run(
            &mut make,
            &format!("install Kerberos directory {directory}"),
        );
    }
}

fn make_command(build_dir: &Path) -> Command {
    let mut command = Command::new(env::var_os("MAKE").unwrap_or_else(|| OsString::from("make")));
    command.current_dir(build_dir);

    // Share Cargo's jobserver instead of starting an unrelated set of jobs.
    if let Some(flags) = env::var_os("CARGO_MAKEFLAGS") {
        command.env("MAKEFLAGS", flags);
    }

    command
}

fn compile_openvas_shim(manifest_dir: &Path, install_dir: &Path) {
    cc::Build::new()
        .file(manifest_dir.join(OPENVAS_KRB5_SOURCE))
        .include(install_dir.join("include"))
        .opt_level(2)
        .compile("openvas-krb5");
}

fn emit_link_directives(install_dir: &Path) {
    println!(
        "cargo:rustc-link-search=native={}",
        install_dir.join("lib").display()
    );
    for library in KRB5_LIBRARIES {
        println!("cargo:rustc-link-lib=static={library}");
    }
    println!("cargo:rustc-link-lib=resolv");
}

fn generate_bindings(manifest_dir: &Path, install_dir: &Path, out_dir: &Path) {
    let header = manifest_dir.join(OPENVAS_KRB5_HEADER);
    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("--target={}", required_var("TARGET")))
        .clang_arg(format!("-I{}", install_dir.join("include").display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate OpenVAS Kerberos bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write OpenVAS Kerberos bindings");
}

fn recreate_directory(path: &Path, description: &str) {
    if path.exists() {
        fs::remove_dir_all(path)
            .unwrap_or_else(|error| panic!("failed to clear {description} directory: {error}"));
    }
    fs::create_dir_all(path)
        .unwrap_or_else(|error| panic!("failed to create {description} directory: {error}"));
}

fn assert_krb5_install(install_dir: &Path) {
    for library in KRB5_LIBRARIES {
        let archive = install_dir.join("lib").join(format!("lib{library}.a"));
        assert!(
            archive.is_file(),
            "Kerberos build did not produce {}",
            archive.display()
        );
    }

    for header in ["krb5.h", "gssapi/gssapi.h", "gssapi/gssapi_krb5.h"] {
        let header = install_dir.join("include").join(header);
        assert!(
            header.is_file(),
            "Kerberos build did not install {}",
            header.display()
        );
    }
}

fn join_command_args(arguments: &[OsString]) -> OsString {
    let mut joined = OsString::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            joined.push(" ");
        }
        joined.push(argument);
    }
    joined
}

fn run(command: &mut Command, action: &str) {
    eprintln!("openvas-krb5-sys: {action}: {command:?}");
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {action}: {error}"));
    assert!(status.success(), "failed to {action}: {status}");
}

fn required_var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("Cargo did not set {name}"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("Cargo did not set {name}")))
}
