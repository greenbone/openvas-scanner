// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod error;

mod assign;
mod call;
mod declare;
mod fork_interpreter;
mod include;
mod interpreter;
mod loop_extension;
mod operator;

pub use error::FunctionError;
pub use error::InterpretError;
pub use error::InterpretErrorKind;
pub use fork_interpreter::*;
pub use interpreter::ContextLifeTimeCapture;
pub use interpreter::Interpreter;

// we expose the other libraries to allow users to use them without having to import them
pub use nasl_builtin_std::{nasl_std_functions, ContextBuilder, KeyDispatcherSet, RegisterBuilder};
pub use nasl_builtin_utils::{
    Context, ContextType, FunctionErrorKind, NaslFunctionRegister, NaslVarRegister, Register,
};
pub use nasl_syntax::{
    load_non_utf8_path, logger, parse, AsBufReader, FSPluginLoader, LoadError, Loader, NaslValue,
    NoOpLoader,
};
