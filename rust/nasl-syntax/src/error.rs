//! Defines TokenErroor and its companion macros.

use core::fmt;
use std::error::Error;

use crate::token::Token;

/// Is used to express errors while parsing.
///
/// It contains:
/// - a string representation as a reason,
/// - maybe an Token if the error occured while expecting or while parsing a Token,
/// - the line number within the rust code it occurs
/// - the filename of the rust code it occurs
/// It should not be initialized directly but used via the defined macros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenError {
    pub(crate) reason: String,
    pub(crate) token: Option<Token>,
    pub(crate) line: u32,
    pub(crate) file: String,
}

/// Creates an TokenError.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{token_error, Token, TokenCategory};
/// token_error!("without a token");
/// token_error!(
///     Token {
///         category: TokenCategory::UnknownSymbol,
///         position: (42, 42),
///     },
///     "with a token"
/// );
/// ```
#[macro_export]
macro_rules! token_error {
    ($reason:expr) => {{
        use $crate::TokenError;
        TokenError::new($reason.to_string(), None, line!(), file!().to_string())
    }};
    ($token:expr, $reason:expr) => {{
        use $crate::TokenError;
        TokenError::new(
            $reason.to_string(),
            Some($token),
            line!(),
            file!().to_string(),
        )
    }};
}

/// Creates an unexpected Token error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{unexpected_token, Token, TokenCategory};
/// unexpected_token!(Token {
///     category: TokenCategory::UnknownSymbol,
///     position: (42, 42),
/// });
/// ```
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

/// Creates an unclosed Token error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{unclosed_token, Token, TokenCategory};
/// unclosed_token!(Token {
///     category: TokenCategory::UnknownSymbol,
///     position: (42, 42),
/// });
/// ```
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

/// Creates an unexpected end error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::unexpected_end;
/// unexpected_end!("within an example.");
/// ```
#[macro_export]
macro_rules! unexpected_end {
    ($reason:expr) => {{
        use $crate::token_error;
        token_error!(format!("Unexpected end: {:?}", $reason))
    }};
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl TokenError {
    /// Creates a new TokenError.
    pub fn new(reason: String, token: Option<Token>, line: u32, file: String) -> Self {
        Self {
            reason,
            token,
            line,
            file,
        }
    }
}

impl Error for TokenError {}
