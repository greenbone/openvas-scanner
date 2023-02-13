use std::path::PathBuf;

use nasl_interpreter::{InterpretError, LoadError};
use nasl_syntax::SyntaxError;
use sink::SinkError;

#[derive(Debug, Clone)]
pub enum CliErrorKind {
    WrongAction,

    PluginPathIsNotADir(PathBuf),
    Openvas {
        args: Option<String>,
        err_msg: String,
    },
    NoExitCall(String),
    InterpretError(InterpretError),
    LoadError(LoadError),
    SinkError(SinkError),
    SyntaxError(SyntaxError),
}

#[derive(Debug, Clone)]
pub struct CliError {
    pub filename: String,
    pub kind: CliErrorKind,
}

impl From<LoadError> for CliErrorKind {
    fn from(value: LoadError) -> Self {
        Self::LoadError(value)
    }
}

impl From<InterpretError> for CliErrorKind {
    fn from(value: InterpretError) -> Self {
        Self::InterpretError(value)
    }
}

impl From<SinkError> for CliErrorKind {
    fn from(value: SinkError) -> Self {
        Self::SinkError(value)
    }
}

impl From<SyntaxError> for CliErrorKind {
    fn from(value: SyntaxError) -> Self {
        Self::SyntaxError(value)
    }
}
