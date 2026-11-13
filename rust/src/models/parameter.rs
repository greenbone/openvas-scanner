// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::Display;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    sqlx::FromRow,
)]
/// Represents a parameter for a VTS configuration.
pub struct Parameter {
    /// The ID of the parameter.
    #[sqlx(rename = "param_id")]
    pub id: u16,
    /// The value of the parameter.
    #[sqlx(rename = "param_value")]
    pub value: String,
}

impl Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.id, self.value)
    }
}
