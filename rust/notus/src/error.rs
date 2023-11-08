use std::fmt::Display;

#[derive(PartialEq, PartialOrd, Debug)]
pub enum NotusError {
    InvalidOS,
    JSONParseError,
    UnsupportedVersion(String),
    NoLoader,
}

impl Display for NotusError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotusError::InvalidOS => todo!(),
            NotusError::JSONParseError => todo!(),
            NotusError::UnsupportedVersion(_) => todo!(),
            NotusError::NoLoader => todo!(),
        }
    }
}
