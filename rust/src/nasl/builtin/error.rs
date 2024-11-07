use thiserror::Error;

use crate::nasl::prelude::*;
use crate::nasl::utils::error::FnErrorKind;

use super::cryptographic::CryptographicError;
use super::http::HttpError;
use super::isotime::IsotimeError;
use super::knowledge_base::KBError;
use super::regex::RegexError;
use super::{misc::MiscError, network::socket::SocketError, ssh::SshError, string::StringError};

#[derive(Debug, Clone, Error)]
pub enum BuiltinError {
    #[error("{0}")]
    Ssh(SshError),
    #[error("{0}")]
    Http(HttpError),
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
    #[error("{0}")]
    Isotime(IsotimeError),
    #[error("{0}")]
    KB(KBError),
    #[cfg(feature = "nasl-builtin-raw-ip")]
    #[error("{0}")]
    PacketForgery(super::raw_ip::PacketForgeryError),
    #[cfg(feature = "nasl-builtin-raw-ip")]
    #[error("{0}")]
    RawIp(super::raw_ip::RawIpError),
}

macro_rules! builtin_error_variant (
    ($err: path, $variant: ident) => {
        impl From<$err> for BuiltinError {
            fn from(value: $err) -> Self {
                BuiltinError::$variant(value).into()
            }
        }

        impl From<$err> for FnError {
            fn from(value: $err) -> Self {
                FnErrorKind::Builtin(BuiltinError::$variant(value).into()).into()
            }
        }

        impl TryFrom<FnError> for $err {
            type Error = ();

            fn try_from(value: FnError) -> Result<Self, Self::Error> {
                match value.kind {
                    FnErrorKind::Builtin(
                        BuiltinError::$variant(e)
                    ) => Ok(e),
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
builtin_error_variant!(HttpError, Http);
builtin_error_variant!(IsotimeError, Isotime);
builtin_error_variant!(RegexError, Regex);
builtin_error_variant!(KBError, KB);

#[cfg(feature = "nasl-builtin-raw-ip")]
builtin_error_variant!(super::raw_ip::PacketForgeryError, PacketForgery);
#[cfg(feature = "nasl-builtin-raw-ip")]
builtin_error_variant!(super::raw_ip::RawIpError, RawIp);
