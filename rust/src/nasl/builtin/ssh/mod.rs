mod error;
mod libssh;

#[cfg(test)]
mod tests;

type SessionId = i32;
pub use self::libssh::Ssh;
