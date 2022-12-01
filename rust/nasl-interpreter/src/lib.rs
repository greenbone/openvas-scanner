use built_in_functions::description;
use context::Register;
use error::{FunctionError, InterpretError};

mod built_in_functions;
mod context;
pub mod error;
mod interpreter;

pub use context::ContextType;
pub use interpreter::{Interpreter, NaslValue};
use nasl_syntax::parse;
use sink::{Sink, SinkError};

pub type NaslFunction = fn(&str, &dyn Sink, &Register) -> Result<NaslValue, FunctionError>;
pub fn lookup(function_name: &str) -> Option<NaslFunction> {
    description::lookup(function_name)
}

/// Defines the mode of the run
pub enum Mode<'a> {
    /// Runs without any kind of prereuists; requires the OID of the script.
    Normal(&'a str),
    /// A Description run will set description to 1 and stores the key as NVTFileName; requires the filename of the script.
    Description(&'a str),
}

impl From<SinkError> for InterpretError {
    fn from(_: SinkError) -> Self {
        Self {
            reason: "somethign horrible when on the DB".to_owned(),
        }
    }
}

pub fn interpret<'a>(
    storage: &dyn Sink,
    mode: Mode,
    code: &'a str,
) -> Vec<Result<NaslValue, InterpretError>> {
    let mut interpreter = match mode {
        Mode::Normal(oid) => Interpreter::new(storage, vec![], Some(oid), None, code),
        Mode::Description(filename) => {
            let initial = vec![(
                "description".to_owned(),
                ContextType::Value(NaslValue::Number(1)),
            )];
            if let Err(err) = storage.store(
                filename,
                sink::StoreType::NVT(sink::NVTField::FileName(filename.to_owned())),
            ) {
                return vec![Err(InterpretError::from(err))];
            }
            Interpreter::new(storage, initial, None, Some(filename), code)
        }
    };

    let mut result = parse(code)
        .map(|stmt| match stmt {
            Ok(stmt) => interpreter.resolve(stmt),
            Err(r) => Err(InterpretError::from(r)),
        })
        .collect();
    match storage.on_exit() {
        Ok(_) => result,
        Err(err) => {
            result.push(Err(InterpretError::from(err)));
            result
        }
    }
}
