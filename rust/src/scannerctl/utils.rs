use std::{net::SocketAddr, path::PathBuf, str::FromStr};

#[derive(Clone)]
pub enum ArgOrStdin<T> {
    Stdin,
    Arg(T),
}

impl<T> FromStr for ArgOrStdin<T>
where
    T: FromStr,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(Self::Stdin)
        } else {
            Ok(Self::Arg(T::from_str(s)?))
        }
    }
}

#[derive(Clone)]
pub enum NotusArgs {
    Address(SocketAddr),
    Internal(PathBuf),
}

impl FromStr for NotusArgs {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse() {
            Ok(Self::Address(addr))
        } else {
            Ok(Self::Internal(PathBuf::from(s)))
        }
    }
}
