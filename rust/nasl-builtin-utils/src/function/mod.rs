//! This module provides machinery to handle typical usecases
//! while parsing the input arguments to NASL functions.

mod from_nasl_value;
mod to_nasl_result;
mod maybe;
mod positionals;
pub mod utils;

pub use to_nasl_result::ToNaslResult;
pub use from_nasl_value::FromNaslValue;
pub use maybe::Maybe;
pub use positionals::Positionals;
pub use positionals::CheckedPositionals;
