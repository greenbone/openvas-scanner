use thiserror::Error;

use crate::nasl::utils::error::ReturnValue;
use crate::nasl::NaslValue;

use super::super::prelude::FunctionErrorKind;
use super::cryptographic::CryptographicError;
use super::http::HttpError;
use super::isotime::IsotimeError;
use super::knowledge_base::KBError;
use super::regex::RegexError;
use super::{misc::MiscError, network::socket::SocketError, ssh::SshError, string::StringError};

#[derive(Debug, Clone, Error)]
#[error("{kind}")]
pub struct BuiltinError {
    kind: BuiltinErrorKind,
    return_value: Option<NaslValue>,
}

#[derive(Debug, Clone, Error)]
pub enum BuiltinErrorKind {
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

impl ReturnValue for BuiltinError {
    fn with_return_value(self, return_value: impl Into<NaslValue>) -> Self {
        Self {
            kind: self.kind,
            return_value: Some(return_value.into()),
        }
    }

    fn get_return_value(&self) -> Option<&NaslValue> {
        self.return_value.as_ref()
    }
}

impl From<BuiltinErrorKind> for BuiltinError {
    fn from(kind: BuiltinErrorKind) -> Self {
        Self {
            kind,
            return_value: None,
        }
    }
}

macro_rules! builtin_error_variant (
    ($err: path, $variant: ident) => {
        impl From<$err> for BuiltinError {
            fn from(value: $err) -> Self {
                BuiltinErrorKind::$variant(value).into()
            }
        }

        impl From<$err> for FunctionErrorKind {
            fn from(value: $err) -> Self {
                FunctionErrorKind::Builtin(BuiltinErrorKind::$variant(value).into())
            }
        }

        impl TryFrom<FunctionErrorKind> for $err {
            type Error = ();

            fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
                match value {
                    FunctionErrorKind::Builtin(
                        BuiltinError {
                            kind: BuiltinErrorKind::$variant(e), ..
                        }
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
