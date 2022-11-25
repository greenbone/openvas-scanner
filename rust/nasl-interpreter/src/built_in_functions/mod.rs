use crate::{interpreter::{Storage, NaslValue}, error::FunctionError, context::NaslContext};

pub mod description;

pub type NaslFunction = fn(& dyn NaslContext, &mut dyn Storage) -> Result<NaslValue, FunctionError>;
