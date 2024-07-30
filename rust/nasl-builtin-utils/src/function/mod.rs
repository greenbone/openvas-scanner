//! This module provides machinery to handle typical usecases
//! while parsing the input arguments to NASL functions.

mod from_nasl_value;
mod maybe;
mod positionals;
mod string_or_data;
mod to_nasl_result;
pub mod utils;

pub use from_nasl_value::FromNaslValue;
pub use maybe::Maybe;
pub use positionals::CheckedPositionals;
pub use positionals::Positionals;
pub use string_or_data::bytes_to_str;
pub use string_or_data::StringOrData;
pub use to_nasl_result::ToNaslResult;
