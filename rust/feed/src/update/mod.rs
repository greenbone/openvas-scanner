mod error;
mod update;
use std::path::Path;

pub use error::Error;
pub use update::Update;

pub enum Key<'a> {
    NASLPath { path: &'a Path, root_dir_len: usize },
}

impl<'a> AsRef<str> for Key<'a> {
    fn as_ref(&self) -> &'a str {
        match self {
            Key::NASLPath { path, root_dir_len } => path
                .to_str()
                .map(|x| &x[*root_dir_len..])
                .unwrap_or_default(),
        }
    }
}
