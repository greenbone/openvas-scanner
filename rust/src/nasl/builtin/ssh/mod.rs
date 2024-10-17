#[cfg(feature = "nasl-builtin-libssh")]
mod libssh;
#[cfg(feature = "nasl-builtin-libssh")]
pub use libssh::{SessionId, Socket, Ssh, SshError};

#[cfg(not(feature = "nasl-builtin-libssh"))]
mod russh;
#[cfg(not(feature = "nasl-builtin-libssh"))]
pub use russh::{SessionId, Socket, Ssh, SshError};

#[cfg(test)]
mod tests;

mod utils;

mod impls;

const MIN_SESSION_ID: SessionId = 9000;
