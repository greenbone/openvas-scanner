// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=install-gcrypt.sh");
    let target = env::var("TARGET").unwrap_or_default();
    let cross = env::var("IN_CROSS").unwrap_or_default();
    let clean = env::var("CLEAN").unwrap_or_default();
    let out = Command::new("sh")
        .arg("install-gcrypt.sh")
        .env("TARGET", target)
        .env("IN_CROSS", cross)
        .env("CLEAN", clean)
        .output();
    match out {
        Ok(out) => {
            match out.status.code() {
                Some(0) | None => {
                    //everything is dandy
                }
                Some(status) => {
                    panic!(
                        "Script exited with {status}:\nstdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
        }
        Err(e) => panic!("Unexpected error: {e}"),
    }
}
