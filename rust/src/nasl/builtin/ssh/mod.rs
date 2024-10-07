mod error;

#[cfg(feature = "nasl-builtin-libssh")]
mod libssh;
#[cfg(feature = "nasl-builtin-libssh")]
mod reexport {
    pub use super::libssh::{
        get_log_level, AuthMethods, AuthStatus, Socket, Ssh, SshKey, SshOption,
    };
    pub use ::libssh_rs::PublicKeyHashType;
}

#[cfg(not(feature = "nasl-builtin-libssh"))]
mod russh;
#[cfg(not(feature = "nasl-builtin-libssh"))]
mod reexport {
    pub use super::russh::{
        get_log_level, AuthMethods, AuthStatus, PublicKeyHashType, Socket, Ssh, SshKey, SshOption,
    };
}

pub use reexport::*;

#[cfg(test)]
mod tests;

mod impls;

type SessionId = i32;
