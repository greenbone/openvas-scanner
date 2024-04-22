// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
/// Represents a parameter for a VTS configuration.
pub struct Parameter {
    /// The ID of the parameter.
    pub id: u16,
    /// The value of the parameter.
    pub value: String,
}
