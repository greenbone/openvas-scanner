use nasl_syntax::SyntaxError;

// TODO refactor error handling
pub struct FunctionError {
    pub reason: String,
}

impl FunctionError {
    pub fn new(reason: String) -> Self {
        Self { reason }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InterpetError {
    pub reason: String,
}

impl InterpetError {
    pub fn new(reason: String) -> Self {
        Self { reason }
    }
}

impl From<SyntaxError> for InterpetError {
    fn from(err: SyntaxError) -> Self {
        InterpetError {
            reason: err.to_string(),
        }
    }
}
