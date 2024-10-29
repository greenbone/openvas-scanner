#[cfg(feature = "nasl-builtin-libssh")]
mod libssh;
#[cfg(feature = "nasl-builtin-libssh")]
pub use libssh::{AuthMethods, SessionId, Socket, SshError, SshSession};

#[cfg(not(feature = "nasl-builtin-libssh"))]
mod russh;
#[cfg(not(feature = "nasl-builtin-libssh"))]
pub use russh::{AuthMethods, SessionId, Socket, SshError, SshSession};

pub use sessions::SshSessions as Ssh;

const MIN_SESSION_ID: SessionId = 9000;

mod impls;
mod sessions;
mod utils;

#[cfg(test)]
mod tests;
