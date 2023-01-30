// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Is a crate to use Statements from nasl-syntax and execute them.
#![warn(missing_docs)]
mod naslvalue;
mod built_in_functions;
use built_in_functions::array;
use built_in_functions::description;
mod error;
use built_in_functions::function;
use built_in_functions::hostname;
use built_in_functions::rand;
use built_in_functions::string;

use error::FunctionError;

mod assign;
mod call;
mod context;
mod declare;
mod include;
mod interpreter;
mod loader;
mod lookup_keys;
mod loop_extension;
mod operator;

pub use context::ContextType;
pub use context::Register;
pub use error::InterpretError;
pub use interpreter::Interpreter;
pub use loader::*;
pub use naslvalue::NaslValue;
use sink::Sink;

// Is a type definition for built-in functions
pub(crate) type NaslFunction = fn(&str, &dyn Sink, &Register) -> Result<NaslValue, FunctionError>;
pub(crate) fn lookup(function_name: &str) -> Option<NaslFunction> {
    description::lookup(function_name)
        .or_else(|| hostname::lookup(function_name))
        .or_else(|| rand::lookup(function_name))
        .or_else(|| string::lookup(function_name))
        .or_else(|| array::lookup(function_name))
        .or_else(|| function::lookup(function_name))
}

