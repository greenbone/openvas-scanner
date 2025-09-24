// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::notus::advisories::VulnerabilityData;

// why????
pub type NotusAdvisory = VulnerabilityData;

#[derive(Clone)]
pub struct NotusCache;
