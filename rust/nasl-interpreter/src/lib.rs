// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod built_in_functions;
mod error;
mod naslvalue;

mod assign;
mod call;
mod context;
mod declare;
mod helper;
mod include;
mod interpreter;
mod loader;
mod logger;
mod lookup_keys;
mod loop_extension;
mod operator;

pub use context::Context;
pub use context::ContextType;
pub use context::DefaultContext;
pub use context::Register;
pub use error::FunctionError;
pub use error::FunctionErrorKind;
pub use error::InterpretError;
pub use error::InterpretErrorKind;

pub use interpreter::Interpreter;
pub use loader::*;
pub use nasl_ssh::*;
pub use logger::{DefaultLogger, Mode, NaslLogger};
pub use naslvalue::NaslValue;

// Is a type definition for built-in functions
pub(crate) type NaslFunction<'a, K> =
    fn(&Register, &Context<K>) -> Result<NaslValue, FunctionErrorKind>;

pub(crate) fn lookup<K>(function_name: &str) -> Option<NaslFunction<K>>
where
    K: AsRef<str>,
{
    built_in_functions::lookup(function_name)

}
