// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Verifies a feed
//!
//! It includes a HashVerifier that loads the hashsum file and verify for each entry that the given
//! hashsum is equal to the calculated hashsum.
//! This is required to prevent load modified nasl scripts.
//! If you want to manipulate the feed you have to create a new hashsum file otherwise the modificated data will not
//! be loaded

use std::{
    fs::File,
    io::{self, BufRead, Cursor},
    path::{Path, PathBuf},
};

use crate::nasl::syntax::{LoadError, Loader};
use hex::encode;
use sha2::{Digest, Sha256};

use openpgp::{
    Cert, KeyHandle,
    parse::Parse,
    parse::stream::{
        DetachedVerifierBuilder, GoodChecksum, MessageLayer, MessageStructure, VerificationHelper,
    },
    policy::StandardPolicy,
};
use sequoia_ipc::keybox::{Keybox, KeyboxRecord};
use sequoia_openpgp::{self as openpgp};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
/// Defines error cases that can happen while verifying
pub enum Error {
    #[error("Incorrect feed.")]
    /// Corrupt sums file
    SumsFileCorrupt(Hasher),
    #[error("Unable to load file: {0}")]
    /// Unable to load the file
    LoadError(#[from] LoadError),
    #[error("Invalid hash for file with key '{key}'. Expected '{expected}', found '{actual}'.")]
    /// Invalid hash.
    HashInvalid {
        /// The hash within the sums file
        expected: String,
        /// The calculated hash
        actual: String,
        /// The key of the file
        key: String,
    },
    #[error("Bad signature: {0}")]
    /// Bad Signature
    BadSignature(String),
    #[error(
        "Signature check is enabled but there is no keyring. Set the GNUPGHOME environment variable"
    )]
    /// Missing keyring
    MissingKeyring,
}

struct VHelper {
    keyring: PathBuf,
    not_before: Option<std::time::SystemTime>,
    not_after: std::time::SystemTime,
}

impl VHelper {
    fn new(keyring: PathBuf) -> Self {
        Self {
            keyring,
            not_before: None,
            not_after: std::time::SystemTime::now(),
        }
    }

    fn load_certs_from_cert_file(&self) -> openpgp::Result<Vec<Cert>> {
        let file = File::open(&self.keyring)?;
        let cert = Cert::from_reader(file)?;
        Ok(vec![cert])
    }

    fn load_certs_from_public_key_bytes(&self) -> openpgp::Result<Vec<Cert>> {
        static PUBLIC_KEY: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/GBCommunitySigningKey.asc"
        ));
        let cursor = Cursor::new(PUBLIC_KEY);
        let cert = Cert::from_reader(cursor)?;
        Ok(vec![cert])
    }

    fn load_certs_from_kbx(&self) -> openpgp::Result<Vec<Cert>> {
        let file = File::open(&self.keyring)?;
        let kbx = Keybox::from_reader(file)?;

        let certs = kbx
            .filter_map(|kbx_record| kbx_record.ok())
            .filter_map(|kbx_record| match kbx_record {
                KeyboxRecord::OpenPGP(r) => Some(r.cert()),
                _ => None,
            })
            .collect::<openpgp::Result<Vec<Cert>>>()?;
        Ok(certs)
    }
}

impl VerificationHelper for VHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        let ext = self
            .keyring
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        match ext.as_deref() {
            Some("kbx") => self.load_certs_from_kbx(),
            Some("asc") | Some("gpg") => self.load_certs_from_cert_file(),
            _ => self.load_certs_from_public_key_bytes(),
        }
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
                                        tracing::warn!("Malformed signature:");
                                    }
                                    (Some(t), Some(not_before), not_after) => {
                                        if t < not_before {
                                            tracing::warn!(
                                                "Signature by {:X} was created before \
                                                 the --not-before date.",
                                                ka.key().fingerprint()
                                            );
                                        } else if t > not_after {
                                            tracing::warn!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint()
                                            );
                                        }
                                    }
                                    (Some(t), None, not_after) => {
                                        if t > not_after {
                                            tracing::warn!(
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

fn pubring() -> Result<PathBuf, Error> {
    // Although using GNUPGHOME is very misleading it is kept due to downwards compatibility reasons
    if let Ok(val) = std::env::var("GNUPGHOME") {
        let kbx = PathBuf::from(val).join("gnupg").join("pubring.kbx");
        if !kbx.is_file() {
            tracing::info!(
                ?kbx,
                "GNUPGHOME does not contain gnupg/pubring.kbx. Falling back to default key"
            );

            Ok(PathBuf::new())
        } else {
            Ok(kbx)
        }
    } else if let Ok(home) = std::env::var("FEED_PUBLIC_KEY") {
        let fpk = PathBuf::from(home);
        if !fpk.is_file() {
            tracing::warn!(?fpk, "Is not pointing to a file.");
            Err(Error::MissingKeyring)
        } else {
            Ok(fpk)
        }
    } else {
        tracing::info!(
            "Signature check is enabled without FEED_PUBLIC_KEY being set. Falling back to default key"
        );
        // we fallback to key inside this binary
        Ok(PathBuf::new())
    }
}

pub fn check_signature<P>(path: &P) -> Result<(), Error>
where
    P: AsRef<Path> + std::fmt::Debug + ?Sized,
{
    let pubring = pubring()?;
    let sign_path = path.as_ref().to_path_buf().join("sha256sums.asc");
    let data_path = path.as_ref().to_path_buf().join("sha256sums");
    tracing::debug!(?pubring, ?sign_path, ?data_path);
    let helper = VHelper::new(pubring);

    let sig_file = File::open(&sign_path).map_err(|x| {
        Error::BadSignature(format!(
            "Unable to check signature {}: {x}.",
            sign_path.to_str().unwrap_or_default()
        ))
    })?;
    let v = DetachedVerifierBuilder::from_reader(sig_file).map_err(|x| {
        Error::BadSignature(format!(
            "Unable to build signatuer verification: {:?}: {x}",
            sign_path
        ))
    })?;
    let p = StandardPolicy::new();
    let mut verifier = v
        .with_policy(&p, None, helper)
        .map_err(|x| Error::BadSignature(format!("Unable to generate verifier: {x}")))?;

    match verifier.verify_file(data_path) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::BadSignature(e.to_string())),
    }
}

/// Trait for signature check
pub trait SignatureChecker {
    /// For signature check the GNUPGHOME environment variable
    /// must be set with the path to the keyring.
    /// If this is satisfied, the signature check is performed
    fn signature_check(feed_path: &str) -> Result<(), Error> {
        check_signature(feed_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Hasher implements the used hashing algorithm to calculate the hashsum
pub enum Hasher {
    /// Sha256
    Sha256,
}

/// Computes hash of a given reader
fn compute_hash_with<H>(
    reader: &mut dyn BufRead,
    hasher: &dyn Fn() -> H,
    key: &str,
) -> Result<String, Error>
where
    H: Digest,
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
    fn hash(&self, reader: &mut dyn BufRead, key: &str) -> Result<String, Error> {
        let hasher = match self {
            Hasher::Sha256 => &Sha256::new,
        };
        compute_hash_with(reader, hasher, key)
    }
}

/// Loads a given hashsums file and lazily verifies the loaded filename key of the sums file and verifies
/// the hash within the sums file with an calculated hash of the found content.
pub struct HashSumNameLoader<'a> {
    reader: &'a Loader,
    hasher: Hasher,
    buf: io::Lines<Box<dyn BufRead>>,
}

/// Loads hashsum verified names of the feed based on a sum file.
impl<'a> HashSumNameLoader<'a> {
    fn new(buf: io::Lines<Box<dyn BufRead>>, reader: &'a Loader, hasher: Hasher) -> Self {
        Self {
            reader,
            hasher,
            buf,
        }
    }

    /// Returns a sha256 implementation of HashSumNameLoader
    pub fn sha256(reader: &'a Loader) -> Result<HashSumNameLoader<'a>, Error> {
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

    pub fn root_path(&self) -> &Path {
        self.reader.root_path()
    }

    pub fn load(&self, file: &str) -> Result<String, LoadError> {
        self.reader.load(file)
    }
}

impl<'a> Iterator for HashSumNameLoader<'a> {
    type Item = Result<HashSumFileItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.buf.next()? {
            Ok(line) => {
                let (hashsum, file_name) = match line.rsplit_once("  ") {
                    Some((hashsum, file_name)) => (hashsum, file_name),
                    None => return Some(Err(Error::SumsFileCorrupt(self.hasher.clone()))),
                };

                Some(Ok(HashSumFileItem {
                    file_name: file_name.to_string(),
                    hashsum: hashsum.to_string(),
                    hasher: Some(self.hasher.clone()),
                    reader: self.reader,
                }))
            }
            Err(_) => Some(Err(Error::SumsFileCorrupt(self.hasher.clone()))),
        }
    }
}

/// Contains all information  necessary to do a hash sum check
pub struct HashSumFileItem<'a> {
    pub file_name: String,
    pub hashsum: String,
    pub hasher: Option<Hasher>,
    pub reader: &'a Loader,
}

impl HashSumFileItem<'_> {
    /// Verifies Hashsum
    pub fn verify(&self) -> Result<(), Error> {
        if let Some(hasher) = &self.hasher {
            let hashsum = hasher.hash(
                &mut self.reader.as_bufreader(&self.file_name)?,
                &self.file_name,
            )?;
            if self.hashsum != hashsum {
                return Err(Error::HashInvalid {
                    expected: self.hashsum.clone(),
                    actual: hashsum,
                    key: self.file_name.clone(),
                });
            }
        }
        Ok(())
    }

    /// returns file name
    pub fn get_filename(&self) -> String {
        self.file_name.clone()
    }

    /// returns hash sum
    pub fn get_hashsum(&self) -> String {
        self.hashsum.clone()
    }
}

fn get_all_plugins(ext: &str, loader: &Loader) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let rp = loader.root_path();
    for e in walkdir::WalkDir::new(rp).into_iter().filter_map(|e| e.ok()) {
        if e.path().extension().is_some_and(|x| x == ext) {
            let relative_path = e.path().strip_prefix(Path::new(&rp)).unwrap();
            files.push(relative_path.to_owned());
        }
    }
    files
}

pub struct NoVerifier<'a> {
    loader: &'a Loader,
    files: Vec<PathBuf>,
}

impl<'a> NoVerifier<'a> {
    pub fn init(ext: &'a str, loader: &'a Loader) -> Self {
        Self {
            loader,
            files: get_all_plugins(ext, loader),
        }
    }

    pub fn nasl(loader: &'a Loader) -> Self {
        Self::init("nasl", loader)
    }

    pub fn notus(loader: &'a Loader) -> Self {
        Self::init("notus", loader)
    }

    pub fn load(&self, filename: &str) -> Result<String, LoadError> {
        self.loader.load(filename)
    }
}

impl<'a> Iterator for NoVerifier<'a> {
    type Item = Result<HashSumFileItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.files.pop().map(|file| {
            // Compute the hash sum in advance so that the
            // check will always succeed.
            let file_name = file.as_path().to_str().unwrap().to_owned();
            Ok(HashSumFileItem {
                file_name,
                hashsum: String::new(),
                hasher: None,
                reader: self.loader,
            })
        })
    }
}
