use crate::nasl::{interpreter::InterpretError, prelude::NaslValue, Register};

pub struct Interpreter {
    _register: Register,
}

pub type InterpretResult = Result<NaslValue, InterpretError>;

impl Interpreter {
    /// Creates a new Interpreter
    pub fn new(_register: Register) -> Self {
        Interpreter { _register }
    }
}
