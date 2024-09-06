// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

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

#[cfg(test)]
mod tests;

pub use code_interpreter::*;
pub use error::FunctionError;
pub use error::InterpretError;
pub use error::InterpretErrorKind;
pub use interpreter::Interpreter;
pub use scanner::ExecuteError;

pub use scanner::DefaultScannerStack;
pub use scanner::ScanRunner;
pub use scanner::Scanner;
pub use scanner::ScannerStackWithStorage;
