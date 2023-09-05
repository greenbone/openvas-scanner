// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// Configuration preference for the scanner
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub struct ScannerPreference {
    /// The ID of the scanner preference.
    pub id: String,
    /// The value of the scanner preference.
    pub value: String,
}
