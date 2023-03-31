//! Verifies a feed
//!
//! It includes a HashVerifier that loads the hashsum file and verify for each entry that the given
//! hashsum is equal to the calculated hashsum.
//! This is required to prevent load modified nasl scripts.
//! If you want to manipulate the feed you have to create a new hashsum file otherwise the modificated data will not
//! be loaded

use std::{
    fmt::Display,
    io::{self, BufRead, BufReader, Read},
};

use hex::encode;
use nasl_interpreter::{AsBufReader, LoadError};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Defines error cases that can happen while verifiying
pub enum Error {
    /// Feed is incorrect
    SumsFileCorrupt(Hasher),
    /// Unable to load the file
    LoadError(LoadError),
    /// When the calculated hash is not the same as in hashsum file.
    HashInvalid {
        /// The hash within the sums file
        expected: String,
        /// The calculated hash
        actual: String,
        /// The key of the file
        key: String,
    },
}

impl From<LoadError> for Error {
    fn from(value: LoadError) -> Self {
        Error::LoadError(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SumsFileCorrupt(e) => write!(f, "{} is corrupted.", e.sum_file()),
            Error::LoadError(e) => write!(f, "{e}"),
            Error::HashInvalid {
                expected,
                actual,
                key,
            } => write!(f, "{key} hash {actual} is not as expected ({expected})."),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Hasher implements the used hashing algorithm to calculate the hashsum
pub enum Hasher {
    /// Sha256
    Sha256,
}

fn compute_hash_with<R, H>(
    reader: &mut BufReader<R>,
    hasher: &dyn Fn() -> H,
    key: &str,
) -> Result<String, Error>
where
    H: Digest,
    R: Read,
{
    let mut buffer = [0; 1024];
    let mut hasher = hasher();
    let ioma = |e| LoadError::from((key, e));

    loop {
        let count = reader.read(&mut buffer).map_err(ioma)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let result = hasher.finalize();
    let result = encode(&result[..]);
    Ok(result)
}
impl Hasher {
    /// Returns the name of the used sums file
    pub fn sum_file(&self) -> &str {
        match self {
            Hasher::Sha256 => "sha256sums",
        }
    }

    fn hash<R>(&self, reader: &mut BufReader<R>, key: &str) -> Result<String, Error>
    where
        R: Read,
    {
        let hasher = match self {
            Hasher::Sha256 => &Sha256::new,
        };
        compute_hash_with(reader, hasher, key)
    }
}

/// Loads a given hashsums file and lazily verifies the loaded filename key of the sums file and verifies
/// the hash within the sums file with an calculated hash of the found content.
pub struct HashSumNameLoader<'a, R> {
    reader: &'a dyn AsBufReader<R>,
    hasher: Hasher,
    buf: io::Lines<BufReader<R>>,
}

/// Loads hashsum verified names of the feed based on a sum file.
impl<'a, R: Read> HashSumNameLoader<'a, R> {
    fn new(buf: io::Lines<BufReader<R>>, reader: &'a dyn AsBufReader<R>, hasher: Hasher) -> Self {
        Self {
            reader,
            hasher,
            buf,
        }
    }

    /// Returns a sha256 implementation of HashSumNameLoader
    pub fn sha256(reader: &'a dyn AsBufReader<R>) -> Result<HashSumNameLoader<'a, R>, Error> {
        let buf = reader
            .as_bufreader(Hasher::Sha256.sum_file())
            .map(|x| x.lines())
            .map_err(|_| Error::SumsFileCorrupt(Hasher::Sha256))?;
        Ok(Self::new(buf, reader, Hasher::Sha256))
    }
}

/// Defines a file name loader to load filenames
pub trait FileNameLoader {
    /// Returns the next filename
    fn next_filename(&mut self) -> Option<Result<String, Error>>;
}

impl<R> FileNameLoader for HashSumNameLoader<'_, R>
where
    R: Read,
{
    fn next_filename(&mut self) -> Option<Result<String, Error>> {
        let verify_sum_line = |l: &str| -> Result<String, Error> {
            let (expected, name) = l
                .rsplit_once("  ")
                .ok_or_else(|| Error::SumsFileCorrupt(self.hasher.clone()))?;
            let actual = self
                .hasher
                .hash(&mut self.reader.as_bufreader(name)?, name)?;
            let name = name.to_owned();
            if actual != expected {
                Err(Error::HashInvalid {
                    expected: expected.into(),
                    actual,
                    key: name,
                })
            } else {
                Ok(name)
            }
        };

        match self.buf.next()? {
            Ok(x) => Some(verify_sum_line(&x)),
            Err(_) => Some(Err(Error::SumsFileCorrupt(self.hasher.clone()))),
        }
    }
}
impl<R> Iterator for HashSumNameLoader<'_, R>
where
    R: Read,
{
    type Item = Result<String, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_filename()
    }
}
