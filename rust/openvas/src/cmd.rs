// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use configparser::ini::Ini;
use std::{
    io::Result,
    process::{Child, Command},
};
/// This module provides functions to call the openvas executable for different
/// purposes, e.g. start or stopping a scan.

/// Check if it is possible to start openvas.
pub fn check() -> bool {
    Command::new("openvas").spawn().is_ok()
}

/// Check if it is possible to start openvas with the sudo command. In most
/// environments it is necessary to start openvas as sudo, as it is not possible
/// to use all functionalities.
pub fn check_sudo() -> bool {
    Command::new("sudo").args(["-n", "openvas"]).spawn().is_ok()
}

/// Read the openvas configuration.
pub fn read_openvas_config() -> Result<Ini> {
    let oconfig = Command::new("openvas").arg("-s").output()?;

    let mut config = Ini::new();
    let oconfig = oconfig.stdout.iter().map(|x| *x as char).collect();
    config
        .read(oconfig)
        .expect("Error reading openvas configuration");
    Ok(config)
}

/// Get the path to the redis unix socket from openvas configuration
pub fn get_redis_socket() -> String {
    if let Ok(config) = read_openvas_config() {
        return match config.get("default", "db_address") {
            Some(setting) => format!("unix://{}", setting),
            None => String::new(),
        };
    }
    String::new()
}

/// Start a new scan with the openvas executable with the given string. Before a scan can be
/// started all data needed for the scan must be put into redis before.
pub fn start(id: &str, sudo: bool, nice: Option<i8>) -> Result<Child> {
    match nice {
        Some(niceness) => match sudo {
            true => Command::new("nice")
                .args([
                    "-n",
                    &niceness.to_string(),
                    "sudo",
                    "-n",
                    "openvas",
                    "--start-scan",
                    id,
                ])
                .spawn(),
            false => Command::new("nice")
                .args(["-n", &niceness.to_string(), "openvas", "--start-scan", id])
                .spawn(),
        },
        None => match sudo {
            true => Command::new("sudo")
                .args(["-n", "openvas", "--start-scan", id])
                .spawn(),
            false => Command::new("openvas").args(["--start-scan", id]).spawn(),
        },
    }
}

/// Stops a running scan. Openvas internally sends an SIGUSR1 to the running
/// openvas scan.
pub fn stop(id: &str, sudo: bool) -> Result<Child> {
    match sudo {
        true => Command::new("sudo")
            .args(["-n", "openvas", "--stop-scan", id])
            .spawn(),
        false => Command::new("openvas").args(["--stop-scan", id]).spawn(),
    }
}
