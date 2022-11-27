use built_in_functions::description;
use context::Register;
use error::FunctionError;

mod built_in_functions;
mod context;
pub mod error;
mod interpreter;

pub use interpreter::{Interpreter, NaslValue, Storage};
pub use context::ContextType;

pub type NaslFunction = fn(&mut dyn Storage, &mut Register) -> Result<NaslValue, FunctionError>;
pub fn lookup(function_name: &str) -> Option<NaslFunction> {
    description::lookup(function_name)
}
