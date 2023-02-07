use std::path::PathBuf;

use nasl_interpreter::{InterpretError, LoadError};
use nasl_syntax::SyntaxError;
use sink::SinkError;

#[derive(Debug, Clone)]
pub enum CliError {
    WrongAction,

    PluginPathIsNotADir(PathBuf),
    Openvas {
        args: Option<String>,
        err_msg: String,
    },
    NoExitCall(String),
}

impl From<LoadError> for CliError {
    fn from(value: LoadError) -> Self {
        todo!()
    }
}

impl From<InterpretError> for CliError {
    fn from(value: InterpretError) -> Self {
        todo!()
    }
}

impl From<SinkError> for CliError {
    fn from(value: SinkError) -> Self {
        todo!()
    }
}

impl From<SyntaxError> for CliError {
    fn from(value: SyntaxError) -> Self {
        todo!()
    }
}
