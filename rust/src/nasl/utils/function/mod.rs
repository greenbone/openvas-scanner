// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module provides machinery to handle typical usecases
//! while parsing the input arguments to NASL functions.

mod from_nasl_value;
mod maybe;
mod positionals;
mod to_nasl_result;
mod types;
pub mod utils;

pub use from_nasl_value::FromNaslValue;
pub use maybe::Maybe;
pub use positionals::CheckedPositionals;
pub use positionals::Positionals;
pub use to_nasl_result::ToNaslResult;
pub use types::bytes_to_str;
pub use types::StringOrData;
