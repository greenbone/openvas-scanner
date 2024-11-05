use thiserror::Error;

use super::super::prelude::NaslError;
use super::cryptographic::CryptographicError;
use super::regex::RegexError;
use super::{misc::MiscError, network::socket::SocketError, ssh::SshError, string::StringError};

#[derive(Debug, Clone, Error)]
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
    #[error("{0}")]
    Regex(RegexError),
    #[cfg(feature = "nasl-builtin-raw-ip")]
    #[error("{0}")]
    PacketForgery(super::raw_ip::PacketForgeryError),
}

macro_rules! builtin_error_variant (
    ($err: path, $variant: ident) => {
        impl From<$err> for BuiltinError {
            fn from(value: $err) -> Self {
                BuiltinError::$variant(value)
            }
        }

        impl From<$err> for NaslError {
            fn from(value: $err) -> Self {
                NaslError::Builtin(BuiltinError::$variant(value))
            }
        }

        impl TryFrom<NaslError> for $err {
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
builtin_error_variant!(RegexError, Regex);
#[cfg(feature = "nasl-builtin-raw-ip")]
builtin_error_variant!(super::raw_ip::PacketForgeryError, PacketForgery);
