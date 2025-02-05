// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models;

use super::StorageType;

pub type NotusAdvisory = models::VulnerabilityData;

pub struct NotusItemType;

impl StorageType for NotusItemType {
    type K = ();
    type V = NotusAdvisory;
}
