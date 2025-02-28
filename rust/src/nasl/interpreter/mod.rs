mod error;

mod assign;
mod call;
mod declare;
mod forking_interpreter;
mod include;
#[allow(clippy::module_inception)]
mod interpreter;
mod loop_extension;
mod operator;

pub use error::{FunctionCallError, InterpretError, InterpretErrorKind};
pub use forking_interpreter::ForkingInterpreter;
pub use interpreter::Interpreter;

#[cfg(test)]
mod tests;
