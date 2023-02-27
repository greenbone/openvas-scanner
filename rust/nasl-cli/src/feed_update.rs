use std::{io, path::PathBuf};

use nasl_interpreter::{
    FSPluginLoader, InterpretError, InterpretErrorKind, Interpreter, LoadError, Loader, NaslValue,
    Register,
};
use nasl_syntax::Statement;
use sink::{nvt::NVTField, Sink, SinkError};
use walkdir::WalkDir;

use crate::{CliError, CliErrorKind};

fn retry_dispatch(sink: &dyn Sink, key: &str, dispatch: sink::Dispatch) -> Result<(), SinkError> {
    match sink.dispatch(key, dispatch.clone()) {
        Ok(_) => Ok(()),
        Err(SinkError::Retry(_)) => retry_dispatch(sink, key, dispatch),
        Err(e) => Err(e),
    }
}

fn retry_interpret(
    interpreter: &mut Interpreter,
    stmt: &Statement,
) -> Result<NaslValue, InterpretError> {
    match interpreter.resolve(stmt) {
        Ok(x) => Ok(x),
        Err(e) => match e.kind {
            InterpretErrorKind::LoadError(LoadError::Retry(_))
            | InterpretErrorKind::IOError(io::ErrorKind::Interrupted)
            | InterpretErrorKind::SinkError(SinkError::Retry(_)) => {
                retry_interpret(interpreter, stmt)
            }
            _ => Err(e),
        },
    }
}

fn load_code(loader: &dyn Loader, key: &str) -> Result<String, CliError> {
    loader
        .load(key)
        .map_err(|e| e.into())
        .map_err(|kind| CliError {
            kind,
            filename: key.to_owned(),
        })
}

fn add_feed_version_to_storage(loader: &dyn Loader, storage: &dyn Sink) -> Result<(), CliError> {
    let code = load_code(loader, "plugin_feed_info.inc")?;
    let mut register = Register::default();
    let mut interpreter = Interpreter::new("inc", storage, loader, &mut register);
    for stmt in nasl_syntax::parse(&code) {
        match stmt {
            Ok(stmt) => retry_interpret(&mut interpreter, &stmt)
                .map_err(|e| e.into())
                .map_err(|kind| CliError {
                    kind,
                    filename: "plugin_feed_info.inc".to_owned(),
                })?,
            Err(e) => {
                return Err(CliError {
                    kind: e.into(),
                    filename: "plugin_feed_info.inc".to_owned(),
                })
            }
        };
    }
    let feed_version = register
        .named("PLUGIN_SET")
        .map(|x| x.to_string())
        .unwrap_or_else(|| "0".to_owned());
    retry_dispatch(storage, "generic", NVTField::Version(feed_version).into()).map_err(|e| {
        CliError {
            filename: "plugin_feed_info.inc".to_owned(),
            kind: e.into(),
        }
    })
}

pub fn run(storage: &dyn Sink, path: PathBuf, verbose: bool) -> Result<(), CliError> {
    if verbose {
        println!("description run syntax in {path:?}.");
    }
    let root_dir = path.clone();
    // needed to strip the root path so that we can build a relative path
    // e.g. 2006/something.nasl
    let root_dir_len = path
        .to_str()
        .map(|x| {
            if x.ends_with('/') {
                x.len()
            } else {
                // we need to skip `/` when the given path
                // does not end with it
                x.len() + 1
            }
        })
        .unwrap_or_default();
    let loader: FSPluginLoader =
        root_dir
            .as_path()
            .try_into()
            .map_err(|e: LoadError| CliError {
                kind: e.into(),
                filename: root_dir.to_str().unwrap_or_default().to_owned(),
            })?;

    // load feed version
    add_feed_version_to_storage(&loader, storage)?;
    let updater = feed::Update::new("1", 5, &loader, storage);

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let ext = {
            if let Some(ext) = entry.path().extension() {
                ext.to_str().unwrap().to_owned()
            } else {
                "".to_owned()
            }
        };
        if matches!(ext.as_str(), "nasl") {
            updater
                .single(&feed::Key::NASLPath {
                    path: entry.path(),
                    root_dir_len,
                })
                .map_err(|e| CliError {
                    filename: entry.path().to_str().unwrap_or_default().to_owned(),
                    kind: e.into(),
                })?;
        }
    }
    Ok(())
}

impl From<feed::UpdateError> for CliErrorKind {
    fn from(value: feed::UpdateError) -> Self {
        match value {
            feed::UpdateError::InterpretError(e) => CliErrorKind::InterpretError(e),
            feed::UpdateError::SyntaxError(e) => CliErrorKind::SyntaxError(e),
            feed::UpdateError::SinkError(e) => CliErrorKind::SinkError(e),
            feed::UpdateError::LoadError(e) => CliErrorKind::LoadError(e),
            feed::UpdateError::MissingExit { key } => CliErrorKind::NoExitCall(key),
        }
    }
}
