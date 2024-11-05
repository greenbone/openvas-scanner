use thiserror::Error;

use super::super::prelude::NaslError;
use super::cryptographic::CryptographicError;
use super::{misc::MiscError, network::socket::SocketError, ssh::SshError, string::StringError};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuiltinError {
    #[error("{0}")]
    Ssh(SshError),
    #[error("{0}")]
    String(StringError),
    #[error("{0}")]
    Misc(MiscError),
    #[error("{0}")]
    Socket(SocketError),
    #[error("{0}")]
    Cryptographic(CryptographicError),
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

        impl TryFrom<NaslError> for $ty {
            type Error = ();

            fn try_from(value: NaslError) -> Result<Self, Self::Error> {
                match value {
                    NaslError::Builtin(BuiltinError::$variant(e)) => Ok(e),
                    _ => Err(()),
                }
            }
        }
    }
);

builtin_error_variant!(StringError, String);
builtin_error_variant!(MiscError, Misc);
builtin_error_variant!(SocketError, Socket);
builtin_error_variant!(CryptographicError, Cryptographic);
builtin_error_variant!(SshError, Ssh);
