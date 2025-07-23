// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod builtin;
mod code;
pub mod error;
pub mod interpreter;
pub mod syntax;
pub mod utils;

#[cfg(test)]
mod test_utils;

#[cfg(feature = "nasl-builtin-raw-ip")]
mod raw_ip_utils {
    pub use super::builtin::raw_ip::raw_ip_utils;
}

pub mod prelude {
    pub use super::builtin::BuiltinError;
    pub use super::code::Code;
    pub use super::interpreter::NaslValue;
    pub use super::interpreter::Register;
    pub use super::syntax::FSPluginLoader;
    pub use super::syntax::Loader;
    pub use super::utils::ArgumentError;
    pub use super::utils::FnError;
    pub use super::utils::NaslResult;
    pub use super::utils::error::Retryable;
    pub use super::utils::error::ReturnValue;
    pub use super::utils::error::WithErrorInfo;
    pub use super::utils::function::CheckedPositionals;
    pub use super::utils::function::FromNaslValue;
    pub use super::utils::function::Positionals;
    pub use super::utils::function::ToNaslResult;
    pub use super::utils::scan_ctx::ScanCtx;
    pub use super::utils::scan_ctx::ScanCtxBuilder;
    pub use super::utils::scan_ctx::ScriptCtx;
    pub use crate::function_set;
    pub use nasl_function_proc_macro::nasl_function;
}

pub use prelude::*;

pub use builtin::nasl_std_functions;

pub use syntax::NoOpLoader;

#[cfg(test)]
mod test_prelude {
    pub use super::prelude::*;
    pub use super::test_utils::DefaultTestBuilder;
    pub use super::test_utils::TestBuilder;
    pub use super::test_utils::check_code_result;
    pub use crate::check_code_result_matches;
    pub use crate::check_err_matches;
}
