// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod error;

mod assign;
mod call;
mod code_interpreter;
mod declare;
mod include;
mod interpreter;
mod loop_extension;
mod operator;
mod scanner;
pub mod scheduling;

pub mod test_utils;

pub use code_interpreter::*;
pub use error::FunctionError;
pub use error::InterpretError;
pub use error::InterpretErrorKind;
pub use interpreter::Interpreter;
pub use scanner::ExecuteError;

pub use scanner::DefaultScannerStack;
pub use scanner::Scanner;
pub use scanner::SyncScanInterpreter;
pub use scanner::WithStorageScannerStack;
// we expose the other libraries to allow users to use them without having to import them
pub use nasl_builtin_std::{nasl_std_functions, ContextFactory, RegisterBuilder};
pub use nasl_builtin_utils::{
    Context, ContextType, FunctionErrorKind, NaslFunctionRegister, NaslVarRegister, Register,
};
pub use nasl_syntax::{
    load_non_utf8_path, parse, AsBufReader, FSPluginLoader, LoadError, Loader, NaslValue,
    NoOpLoader,
};
