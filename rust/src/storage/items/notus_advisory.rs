// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models;

pub type NotusAdvisory = models::VulnerabilityData;

#[derive(Clone)]
pub struct NotusCache;
