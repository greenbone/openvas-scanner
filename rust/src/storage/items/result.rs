// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::{models, storage::ScanID};

pub type ResultItem = models::Result;

pub type ResultContextKeySingle = (ScanID, usize);
