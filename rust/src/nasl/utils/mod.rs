// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
pub mod error;
mod executor;
pub mod function;
pub mod hosts;
pub mod lookup_keys;
pub mod scan_ctx;

pub use super::interpreter::Register;
pub use error::ArgumentError;
pub use error::FnError;
pub use error::InternalError;
pub use scan_ctx::{ScanCtx, ScriptCtx};

pub use executor::{Executor, IntoFunctionSet, NaslFunction, StoredFunctionSet};

use crate::nasl::interpreter::NaslValue;

/// The result of a function call.
pub type NaslResult = Result<NaslValue, FnError>;

/// Resolves positional arguments from the register.
pub fn resolve_positional_arguments(register: &Register) -> Vec<NaslValue> {
    match register.nasl_value(lookup_keys::FC_ANON_ARGS) {
        Ok(NaslValue::Array(arr)) => arr.to_vec(),
        Ok(unexpected) => {
            tracing::warn!(
                "expected array but got: {:?}. Maybe {} was overridden. Ignoring.",
                unexpected,
                lookup_keys::FC_ANON_ARGS
            );
            vec![]
        }
        Err(_) => vec![],
    }
}

/// Allows the definition of global variables
/// belonging to certain builtin functions.
// This is currently only used with `experimental` feature,
// so we mark it as public in order to save many feature gates.
pub trait DefineGlobalVars {
    fn get_global_vars() -> Vec<(&'static str, NaslValue)>;
}
