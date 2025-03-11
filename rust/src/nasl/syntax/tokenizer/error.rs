use std::ops::Range;

use thiserror::Error;

use crate::nasl::error::AsCodespanError;

#[derive(Debug)]
pub struct TokenizerError {
    pub kind: TokenizerErrorKind,
    pub range: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TokenizerErrorKind {}

impl AsCodespanError for TokenizerError {
    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}
