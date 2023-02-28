// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::NaslFunction;

pub mod hmac;

pub(crate) fn lookup(function_name: &str) -> Option<NaslFunction> {
    hmac::lookup(function_name)
}
