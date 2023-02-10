// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{lookup_keys::FC_ANON_ARGS, ContextType, NaslValue, Register};

pub mod array;
pub mod cryptography;
pub mod description;
pub mod function;
pub mod hostname;
pub mod misc;
pub mod string;

pub(crate) fn resolve_positional_arguments(register: &Register) -> Vec<NaslValue> {
    match register.named(FC_ANON_ARGS).cloned() {
        Some(ContextType::Value(NaslValue::Array(arr))) => arr,
        _ => vec![],
    }
}
