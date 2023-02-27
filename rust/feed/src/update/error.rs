use nasl_interpreter::{InterpretError, LoadError};
use nasl_syntax::SyntaxError;
use sink::SinkError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InterpretError(InterpretError),
    SyntaxError(SyntaxError),
    SinkError(SinkError),
    LoadError(LoadError),
    MissingExit { key: String },
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
