//! This module provides machinery to handle typical usecases
//! while parsing the input arguments to NASL functions.

mod from_nasl_value;
mod to_nasl_value;
pub mod utils;

pub use self::to_nasl_value::ToNaslValue;
pub use from_nasl_value::FromNaslValue;
