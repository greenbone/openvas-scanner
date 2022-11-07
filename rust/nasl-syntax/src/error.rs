use core::fmt;
use std::{error::Error, ops::Range};

use crate::token::Token;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenError {
    pub(crate) reason: String,
    pub(crate) token: Option<Token>,
    pub(crate) code_location: Option<Range<usize>>,
    pub(crate) line: u32,
    pub(crate) file: String,
}

#[macro_export]
macro_rules! token_error {
    ($reason:expr) => {
        TokenError {
            reason: $reason,
            token: None,
            code_location: None,
            line: line!(),
            file: file!().to_string(),
        }
    };
    ($token:expr, $reason:expr) => {
        TokenError {
            reason: $reason,
            token: Some($token),
            code_location: None,
            line: line!(),
            file: file!().to_string(),
        }
    };
}

#[macro_export]
macro_rules! unexpected_token {
    ($token:expr) => {{
        use $crate::token_error;
        token_error!(
            $token,
            format!("Unexpected Token {:?}", $token.category()).to_string()
        )
    }};
}

#[macro_export]
macro_rules! unclosed_token {
    ($token:expr) => {{
        use $crate::token_error;
        token_error!(
            $token,
            format!("Unclosed {:?}", $token.category()).to_string()
        )
    }};
}

#[macro_export]
macro_rules! unexpected_end {
    ($reason:expr) => {{
        use $crate::token_error;
        token_error!(format!("Unexpected end: {:?}", $reason))
    }};
}

impl TokenError {
    fn position(&self) -> (usize, usize) {
        self.token.map(|t| t.position).unwrap_or((0, 0))
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn range(&self) -> Range<usize> {
        match self.code_location.clone() {
            Some(x) => x,
            None => {
                let (start, end) = self.position();
                Range { start, end }
            }
        }
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl Error for TokenError {}
