use nasl_interpreter::{InterpretError, LoadError};
use nasl_syntax::SyntaxError;
use sink::SinkError;

use crate::verify;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Errors within feed handling
pub enum Error {
    /// An InterpretError occurred while interpreting
    InterpretError(InterpretError),
    /// NASL script contains an SyntaxError
    SyntaxError(SyntaxError),
    /// Sink is unable to handle operation
    SinkError(SinkError),
    /// Loader is unable to handle operation
    LoadError(LoadError),
    /// Description if block without exit
    MissingExit(String),
    /// Describes an error while verifying the file
    VerifyError(verify::Error),
}

impl From<LoadError> for Error {
    fn from(value: LoadError) -> Self {
        Error::LoadError(value)
    }
}

impl From<SinkError> for Error {
    fn from(value: SinkError) -> Self {
        Error::SinkError(value)
    }
}

impl From<SyntaxError> for Error {
    fn from(value: SyntaxError) -> Self {
        Error::SyntaxError(value)
    }
}

impl From<InterpretError> for Error {
    fn from(value: InterpretError) -> Self {
        Error::InterpretError(value)
    }
}
