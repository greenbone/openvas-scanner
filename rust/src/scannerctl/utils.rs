use std::str::FromStr;

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
