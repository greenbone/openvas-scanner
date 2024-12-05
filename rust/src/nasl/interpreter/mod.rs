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
#[allow(clippy::module_inception)]
mod interpreter;
mod loop_extension;
mod operator;

#[cfg(test)]
mod tests;

pub use code_interpreter::*;
pub use error::FunctionCallError;
pub use error::InterpretError;
pub use error::InterpretErrorKind;
pub use interpreter::Interpreter;
