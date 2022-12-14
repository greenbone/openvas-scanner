use built_in_functions::description;
use context::Register;
use error::{FunctionError, InterpretError};

mod built_in_functions;
mod call;
mod assign;
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
    /// Runs without any kind of prerequisites; requires the OID of the script.
    Normal(&'a str),
    /// A Description run will set description to 1 and stores the key as NVTFileName; requires the filename of the script.
    Description(&'a str),
}

impl From<SinkError> for InterpretError {
    fn from(_: SinkError) -> Self {
        Self {
            reason: "something horrible when on the DB".to_owned(),
        }
    }
}

pub fn interpret<'a>(
    storage: &dyn Sink,
    mode: Mode,
    code: &'a str,
) -> Result<NaslValue, InterpretError> {
    let mut interpreter = match mode {
        Mode::Normal(oid) => Interpreter::new(storage, vec![], Some(oid), None, code),
        Mode::Description(filename) => {
            let initial = vec![(
                "description".to_owned(),
                ContextType::Value(NaslValue::Number(1)),
            )];
            if let Err(err) = storage.dispatch(
                filename,
                sink::Dispatch::NVT(sink::nvt::NVTField::FileName(filename.to_owned())),
            ) {
                return Err(InterpretError::from(err));
            }
            Interpreter::new(storage, initial, None, Some(filename), code)
        }
    };

    let result = parse(code)
        .map(|stmt| match stmt {
            Ok(stmt) => interpreter.resolve(stmt),
            Err(r) => Err(InterpretError::from(r)),
        })
        .last()
        // for the case of NaslValue that returns nothing
        .unwrap_or(Ok(NaslValue::Exit(0)));
    let result = result.map(|x| match x {
        NaslValue::Exit(rc) => NaslValue::Exit(rc),
        _ => NaslValue::Exit(0),
    });
    match storage.on_exit() {
        Ok(_) => result,
        Err(err) => Err(InterpretError::from(err)),
    }
}
