// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Verifies a feed
//!
//! It includes a HashVerifier that loads the hashsum file and verify for each entry that the given
//! hashsum is equal to the calculated hashsum.
//! This is required to prevent load modified nasl scripts.
//! If you want to manipulate the feed you have to create a new hashsum file otherwise the modificated data will not
//! be loaded

use std::{
    fmt::Display,
    fs::File,
    io::{self, BufRead, BufReader, Read},
};

use hex::encode;
use nasl_interpreter::{AsBufReader, LoadError};
use sha2::{Digest, Sha256};

use openpgp::{
    parse::stream::{
        DetachedVerifierBuilder, GoodChecksum, MessageLayer, MessageStructure, VerificationHelper,
    },
    parse::Parse,
    policy::StandardPolicy,
    Cert, KeyHandle,
};
use sequoia_ipc::keybox::{Keybox, KeyboxRecord};
use sequoia_openpgp as openpgp;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Defines error cases that can happen while verifying
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
    /// When signature check of the hashsumfile fails
    BadSignature(String),
    /// Signature is Disabled
    SignatureCheckDisabled,
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
            Error::BadSignature(e) => write!(f, "{e}"),
            Error::SignatureCheckDisabled => write!(
                f,
                "Signature check disabled. To enable it, set the GNUPGHOME environment variable"
            ),
        }
    }
}

struct VHelper {
    keyring: String,
    not_before: Option<std::time::SystemTime>,
    not_after: std::time::SystemTime,
}

impl VHelper {
    fn new(keyring: String) -> Self {
        Self {
            keyring,
            not_before: None,
            not_after: std::time::SystemTime::now(),
        }
    }
}

impl VerificationHelper for VHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        let file = File::open(self.keyring.as_str())?;
        let kbx = Keybox::from_reader(file)?;

        let certs = kbx
            // Keep only records which were parsed successfully.
            .filter_map(|kbx_record| kbx_record.ok())
            // Map the OpenPGP records to the contained certs.
            .filter_map(|kbx_record| match kbx_record {
                KeyboxRecord::OpenPGP(r) => Some(r.cert()),
                _ => None,
            })
            .collect::<openpgp::Result<Vec<Cert>>>()?;
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } => {
                    for result in results {
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                match (
                                    sig.signature_creation_time(),
                                    self.not_before,
                                    self.not_after,
                                ) {
                                    (None, _, _) => {
                                        eprintln!("Malformed signature:");
                                    }
                                    (Some(t), Some(not_before), not_after) => {
                                        if t < not_before {
                                            eprintln!(
                                                "Signature by {:X} was created before \
                                                 the --not-before date.",
                                                ka.key().fingerprint()
                                            );
                                        } else if t > not_after {
                                            eprintln!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint()
                                            );
                                        }
                                    }
                                    (Some(t), None, not_after) => {
                                        if t > not_after {
                                            eprintln!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint()
                                            );
                                        }
                                    }
                                };
                            }
                            Err(e) => return Err(anyhow::Error::msg(e.to_string())),
                        }
                    }
                }
                MessageLayer::Compression { .. } => (),
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

pub fn signature_check(feed_path: &str) -> Result<(), Error> {
    let mut gnupghome = match std::env::var("GNUPGHOME") {
        Ok(v) => v,
        Err(_) => {
            return Err(Error::SignatureCheckDisabled);
        }
    };
    gnupghome.push_str("/pubring.kbx");

    let helper = VHelper::new(gnupghome);

    let mut sign_path = feed_path.to_owned();
    sign_path.push_str("/sha256sums.asc");
    let mut sig_file = File::open(sign_path).unwrap();
    let mut signature = Vec::new();
    let _ = sig_file.read_to_end(&mut signature);

    let mut data_path = feed_path.to_owned();
    data_path.push_str("/sha256sums");
    let mut data_file = File::open(data_path).unwrap();
    let mut data = Vec::new();
    let _ = data_file.read_to_end(&mut data);

    let v = match DetachedVerifierBuilder::from_bytes(&signature[..]) {
        Ok(v) => v,
        Err(_) => {
            return Err(Error::BadSignature(
                "Siganture verification failed".to_string(),
            ));
        }
    };

    let p = &StandardPolicy::new();
    if let Ok(mut verifier) = v.with_policy(p, None, helper) {
        match verifier.verify_bytes(data) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(Error::BadSignature(e.to_string())),
        }
    };
    Err(Error::BadSignature(
        "Siganture verification failed".to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Hasher implements the used hashing algorithm to calculate the hashsum
pub enum Hasher {
    /// Sha256
    Sha256,
}

/// Computes hash of a given reader
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

    /// Returns the hash of a given reader and key
    pub fn hash<R>(&self, reader: &mut BufReader<R>, key: &str) -> Result<String, Error>
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
            .map_err(Error::LoadError)?;
        Ok(Self::new(buf, reader, Hasher::Sha256))
    }

    /// Returns the hashsum of the sums file
    pub fn sumfile_hash(&self) -> Result<String, Error> {
        self.hasher.hash(
            &mut self.reader.as_bufreader(self.hasher.sum_file())?,
            self.hasher.sum_file(),
        )
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
