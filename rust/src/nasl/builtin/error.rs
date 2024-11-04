use thiserror::Error;

use super::super::prelude::NaslError;
use super::{misc::MiscError, network::socket::SocketError, ssh::SshError, string::StringError};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuiltinError {
    #[error("Authentication error.")]
    Authentication,
    #[error("{0}")]
    Ssh(SshError),
    #[error("{0}")]
    String(StringError),
    #[error("{0}")]
    Misc(MiscError),
    #[error("{0}")]
    Socket(SocketError),
}

macro_rules! builtin_error_variant (
    ($ty: ty, $variant: ident) => {
        impl From<$ty> for BuiltinError {
            fn from(value: $ty) -> Self {
                BuiltinError::$variant(value)
            }
        }

        impl From<$ty> for NaslError {
            fn from(value: $ty) -> Self {
                NaslError::Builtin(BuiltinError::$variant(value))
            }
        }
    }
);

builtin_error_variant!(StringError, String);
builtin_error_variant!(MiscError, Misc);
builtin_error_variant!(SocketError, Socket);
