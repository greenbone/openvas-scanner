use crate::{interpreter::{NaslContext, Storage, NaslValue}, error::FunctionError};

pub type NaslFunction = fn(& dyn NaslContext, &mut dyn Storage) -> Result<NaslValue, FunctionError>;