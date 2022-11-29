use nasl_syntax::SyntaxError;

// TODO refactor error handling
#[derive(Debug)]
pub struct FunctionError {
    pub reason: String,
}

impl FunctionError {
    pub fn new(reason: String) -> Self {
        Self { reason }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InterpretError {
    pub reason: String,
}

impl InterpretError {
    pub fn new(reason: String) -> Self {
        Self { reason }
    }
}

impl From<SyntaxError> for InterpretError {
    fn from(err: SyntaxError) -> Self {
        InterpretError {
            reason: err.to_string(),
        }
    }
}
