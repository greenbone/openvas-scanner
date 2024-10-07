mod error;

#[cfg(feature = "nasl-builtin-libssh")]
mod libssh;
#[cfg(feature = "nasl-builtin-libssh")]
pub use self::libssh::Ssh;

#[cfg(not(feature = "nasl-builtin-libssh"))]
mod russh;
#[cfg(not(feature = "nasl-builtin-libssh"))]
pub use self::russh::Ssh;

#[cfg(test)]
mod tests;

type SessionId = i32;
