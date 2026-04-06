// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub fn show_version(binary_name: &str) {
    tracing::info!(
        "Running {binary_name} version {}",
        option_env!("VERGEN_GIT_DESCRIBE").unwrap_or("unknown")
    );
}
