// TODO refactor error handling
pub struct FunctionError {
    pub reason: String,
}

impl FunctionError {
    pub fn new(reason: String) -> Self{
        Self { reason }
    }
}

#[derive(Debug, PartialEq)]
pub struct InterpetError{
    pub reason: String,
}

impl InterpetError {
    pub fn new(reason: String) -> Self{
        Self { reason: reason }
    }
}