// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
pub mod context;
pub mod error;
mod executor;
pub mod function;
pub mod hosts;
pub mod lookup_keys;

use std::collections::HashMap;

pub use context::{Context, ContextType, Register};
pub use error::ArgumentError;
pub use error::FnError;
pub use error::InternalError;

pub use executor::{Executor, IntoFunctionSet, NaslFunction, StoredFunctionSet};

/// The result of a function call.
pub type NaslResult = Result<crate::nasl::syntax::NaslValue, FnError>;

/// Resolves positional arguments from the register.
pub fn resolve_positional_arguments(register: &Register) -> Vec<crate::nasl::syntax::NaslValue> {
    match register.named(lookup_keys::FC_ANON_ARGS).cloned() {
        Some(ContextType::Value(crate::nasl::syntax::NaslValue::Array(arr))) => arr,
        Some(unexpected) => {
            tracing::warn!(
                "expected array but got: {:?}. Maybe {} was overridden. Ignoring.",
                unexpected,
                lookup_keys::FC_ANON_ARGS
            );
            vec![]
        }
        None => vec![],
    }
}

/// gets a named parameter
///
/// The function name is required for the error cases that can occur when either the found
/// parameter is a function or when required is set to true and no parameter was found.
///
/// Additionally when a parameter is not required it will return Exit(0) instead of Null. This is
/// done to allow differentiation between a parameter that is set to Null on purpose.
pub fn get_named_parameter<'a>(
    registrat: &'a Register,
    key: &'a str,
    required: bool,
) -> Result<&'a crate::nasl::syntax::NaslValue, ArgumentError> {
    match registrat.named(key) {
        None => {
            if required {
                Err(ArgumentError::MissingNamed(vec![key.to_owned()]))
            } else {
                // we use exit because a named value can be intentionally set to null and may be
                // treated differently when it is not set compared to set but null.
                Ok(&crate::nasl::syntax::NaslValue::Exit(0))
            }
        }
        Some(ct) => match ct {
            ContextType::Value(value) => Ok(value),
            _ => Err(ArgumentError::wrong_argument(key, "value", "function")),
        },
    }
}

/// Is a type definition for built-in variables
///
/// It is mostly used internally when building a NaslVarDefiner.
pub type NaslVars<'a> = HashMap<&'a str, crate::nasl::syntax::NaslValue>;

/// Looks for NaslVars.
pub trait NaslVarDefiner {
    /// Returns a NaslVars if it is registered.
    fn nasl_var_define(&self) -> NaslVars;
}

/// Holds registered NaslVarDefiner
#[derive(Default)]
pub struct NaslVarRegister {
    /// Holds all NaslVars definers
    pub definers: Vec<Box<dyn NaslVarDefiner>>,
}

impl NaslVarRegister {
    /// Creates a new NaslVarRegister
    pub fn new(definer: Vec<Box<dyn NaslVarDefiner>>) -> Self {
        Self { definers: definer }
    }
}

/// A builder for NaslVarRegister
#[derive(Default)]
pub struct NaslVarRegisterBuilder {
    definer: Vec<Box<dyn NaslVarDefiner>>,
}

impl NaslVarRegisterBuilder {
    /// Creates a new NaslVarRegister builder
    pub fn new() -> Self {
        Self {
            definer: Vec::new(),
        }
    }
    /// Push a declared NaslVarDefiner into the definer list
    pub fn push_register<T>(mut self, definer: T) -> Self
    where
        T: NaslVarDefiner + 'static,
    {
        self.definer.push(Box::new(definer));
        self
    }

    /// Build a NaslVarRegister with a vector of NaslVarsDefiner
    pub fn build(self) -> NaslVarRegister {
        NaslVarRegister::new(self.definer)
    }
}
