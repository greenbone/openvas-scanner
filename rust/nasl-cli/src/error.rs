use std::path::PathBuf;

use feed::VerifyError;
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
    Corrupt(VerifyError),
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

impl From<feed::UpdateError> for CliError{
    fn from(value: feed::UpdateError) -> Self {
        match value {
            feed::UpdateError::InterpretError(e) => CliErrorKind::InterpretError(e),
            feed::UpdateError::SyntaxError(e) => CliErrorKind::SyntaxError(e),
            feed::UpdateError::SinkError(e) => CliErrorKind::SinkError(e),
            feed::UpdateError::LoadError(e) => CliErrorKind::LoadError(e),
            feed::UpdateError::MissingExit(key) => CliErrorKind::NoExitCall(key),
            feed::UpdateError::VerifyError(e) => CliErrorKind::Corrupt(e),
        }.into()
    }
}

impl From<feed::VerifyError> for CliError {
    fn from(value: feed::VerifyError) -> Self {
        let filename = match &value {
            VerifyError::SumsFileCorrupt(k) => k.sum_file().to_owned(),
            VerifyError::LoadError(le) => load_error_to_string(le),
            VerifyError::HashInvalid {
                expected: _,
                actual: _,
                key,
            } => key.to_owned(),
        };

        CliError {filename, kind: CliErrorKind::Corrupt(value)}
    }
}

fn load_error_to_string(le: &LoadError) -> String {
    match le {
        LoadError::Retry(f) => f,
        LoadError::NotFound(f) => f,
        LoadError::PermissionDenied(f) => f,
        LoadError::Dirty(f) => f,
    }
    .to_owned()
}

impl From<CliErrorKind> for CliError {
    fn from(value: CliErrorKind) -> Self {
        let filename = match &value {
            CliErrorKind::WrongAction => "".to_owned(),
            CliErrorKind::PluginPathIsNotADir(s) => {
                s.as_os_str().to_str().unwrap_or_default().to_owned()
            }
            CliErrorKind::Openvas {
                args: _,
                err_msg: _,
            } => "openvas".to_owned(),
            CliErrorKind::NoExitCall(s) => s.to_owned(),
            //TODO update error needs to enrich with filename
            CliErrorKind::InterpretError(_) => "missing".to_owned(),
            CliErrorKind::LoadError(le) => load_error_to_string(le),
            CliErrorKind::SinkError(s) => match s {
                SinkError::Retry(f) => f,
                SinkError::ConnectionLost(f) => f,
                SinkError::UnexpectedData(f) => f,
                SinkError::Dirty(f) => f,
            }
            .to_owned(),
            // TODO update error needs to enrich with filename
            CliErrorKind::SyntaxError(_) => "missing".to_owned(),
            CliErrorKind::Corrupt(v) => return CliError::from(v.clone()),
        };
        CliError {
            filename,
            kind: value,
        }
    }
}
