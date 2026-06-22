// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use clap::builder::TypedValueParser;
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub enum ScannerType {
    #[serde(rename = "ospd")]
    #[default]
    Ospd,
    #[serde(rename = "openvas")]
    Openvas,
    #[serde(rename = "openvasd")]
    Openvasd,
    #[serde(rename = "lambda")]
    Lambda,
}

impl TypedValueParser for ScannerType {
    type Value = ScannerType;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Ok(match value.to_str().unwrap_or_default() {
            "ospd" => ScannerType::Ospd,
            "openvas" => ScannerType::Openvas,
            "openvasd" => ScannerType::Openvasd,
            x => {
                let mut cmd = cmd.clone();
                let err = cmd.error(
                    clap::error::ErrorKind::InvalidValue,
                    format!("`{x}` is not a scanner type."),
                );
                return Err(err);
            }
        })
    }
}
