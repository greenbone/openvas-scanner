// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
use async_trait::async_trait;
use std::fmt::Display;

use sqlx::Sqlite;

use v1::V1Crypter;
use v2::V2Crypter;

mod v1;
mod v2;

/// The latest encryption method version.
pub const VERSION: u8 = 2;

#[async_trait]
pub trait Crypt {
    async fn encrypt(&self, data: Vec<u8>) -> anyhow::Result<Encrypted>;
    async fn decrypt(&self, encrypted: Encrypted) -> anyhow::Result<Vec<u8>>;
}

/// Unified encryption access point.
///
/// Allows encryption with the latest version and backwards compatible decryption with all versions.
pub struct Crypter {
    v1: V1Crypter,
    v2: V2Crypter,
}

impl Crypter {
    pub fn new(keyphrase: &[u8], salt: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            v1: V1Crypter::new(keyphrase)?,
            v2: V2Crypter::new(keyphrase, salt)?,
        })
    }
}

#[async_trait]
impl Crypt for Crypter {
    /// Encrypts data using the latest encryption method.
    async fn encrypt(&self, data: Vec<u8>) -> anyhow::Result<Encrypted> {
        let key = self.v2.key;
        tokio::task::spawn_blocking(move || v2::V2Crypter::encrypt_sync(&key, data)).await?
    }

    /// Decrypts data using the encryption method embedded in the metadata.
    async fn decrypt(&self, encrypted: Encrypted) -> anyhow::Result<Vec<u8>> {
        match encrypted.version {
            1 => {
                let key = self.v1.key;
                tokio::task::spawn_blocking(move || V1Crypter::decrypt_sync(&key, &encrypted))
                    .await?
            }
            2 => {
                let key = self.v2.key;
                tokio::task::spawn_blocking(move || V2Crypter::decrypt_sync(&key, &encrypted))
                    .await?
            }
            _ => Err(anyhow::anyhow!("unsupported encryption version")),
        }
    }
}

/// Encrypted data container.
#[derive(Clone, Debug)]
pub struct Encrypted {
    /// Used encryption method version.
    version: u8,
    nonce: [u8; 12],
    data: Vec<u8>,
}

impl Display for Encrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::{display::Base64Display, engine::general_purpose::STANDARD};

        let nonce = Base64Display::new(&self.nonce, &STANDARD);
        let data = Base64Display::new(&self.data, &STANDARD);
        write!(f, "{} {nonce} {data}", self.version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    MissingNonce,
    MissingData,
    InvalidVersion,
    InvalidNonce,
    InvalidData,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseError::*;
        match self {
            MissingNonce => write!(f, "missing nonce"),
            MissingData => write!(f, "missing data"),
            InvalidVersion => write!(f, "invalid version"),
            InvalidNonce => write!(f, "invalid nonce"),
            InvalidData => write!(f, "invalid data"),
        }
    }
}

impl std::error::Error for ParseError {}

impl TryFrom<&str> for Encrypted {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        use base64::{Engine as _, engine::general_purpose};
        let mut parts = s.split_whitespace().peekable();
        let decode = |s: &str, e: ParseError| {
            general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(|_| e)
        };

        let version = parts
            // if a version is present it can be 3 bytes at most anything else is either a nonce
            // or corrupted data
            .next_if(|x| x.len() <= 3)
            .map(|x| {
                x.parse::<u8>()
                    .map_err(|_| ParseError::InvalidVersion)
                    .and_then(|x| {
                        if (1..=VERSION).contains(&x) {
                            Ok(x)
                        } else {
                            Err(ParseError::InvalidVersion)
                        }
                    })
            })
            // assume a legacy format with just nounce and data, use version 1
            .unwrap_or(Ok(1))?;

        let nonce = parts
            .next()
            .map(|nonce| decode(nonce, ParseError::InvalidNonce))
            .ok_or(ParseError::MissingNonce)??;

        let data = parts
            .next()
            .map(|nonce| decode(nonce, ParseError::InvalidData))
            .ok_or(ParseError::MissingData)??;

        Ok(Encrypted {
            version,
            nonce: nonce.try_into().map_err(|_| ParseError::InvalidNonce)?,
            data,
        })
    }
}

impl TryFrom<String> for Encrypted {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Encrypted::try_from(s.as_str())
    }
}

pub(crate) async fn get_salt<'a, E>(pool: E) -> Result<Vec<u8>, sqlx::error::Error>
where
    E: sqlx::Executor<'a, Database = Sqlite> + Clone,
{
    // generating a new salt, whether it is needed or not, is faster than using two
    // separate database queries instead
    let salt = argon2::password_hash::generate_salt();

    // inserts the salt if one doesn't exist already, otherwise return the value from the database
    sqlx::query_scalar(
        r#"
        INSERT INTO settings (name, value)
        VALUES ("salt", ?)
        ON CONFLICT(name)
        DO UPDATE SET value = settings.value
        RETURNING value"#,
    )
    .bind(&salt[..])
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encrypt_decrypt() {
        let data = b"Hello, world!".to_vec();
        let encryptor = Crypter::new("keyphrase".as_bytes(), &[0u8; 8]).unwrap();
        let encrypted = encryptor.encrypt(data.clone()).await.unwrap();
        let decrypted = encryptor.decrypt(encrypted).await.unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn encrypted_string_handling() {
        let encrypted = Encrypted {
            version: 1,
            nonce: [0u8; 12],
            data: b"Hello, world!".to_vec(),
        };
        let encrypted = encrypted.to_string();
        assert_eq!(encrypted, "1 AAAAAAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==");
        let encrypted = Encrypted::try_from(encrypted).unwrap();
        assert_eq!(encrypted.nonce, [0u8; 12]);
        assert_eq!(encrypted.data, b"Hello, world!".to_vec());
    }

    #[test]
    fn encrypted_string_handling_missing_version() {
        let encrypted = "AAAAAAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==";
        let encrypted = Encrypted::try_from(encrypted).unwrap();
        assert_eq!(encrypted.version, 1);
    }

    #[test]
    fn encrypted_string_handling_invalid_version() {
        let encrypted = "ABC AAAAAAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==";
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::InvalidVersion);
    }

    #[test]
    fn encrypted_string_handling_unsupported_version() {
        let encrypted = format!(
            "{} AAAAAAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==",
            super::VERSION + 1
        );
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::InvalidVersion);
    }

    #[test]
    fn encrypted_string_handling_missing_data() {
        let encrypted = "AAAAAAAAAAAAAAAASGVsbG8sIHdvcmxkIQ==".to_string();
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::MissingData);
    }

    #[test]
    fn encrypted_string_handling_missing_nonce() {
        let encrypted = "".to_string();
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::MissingNonce);
    }

    #[test]
    fn encrypted_string_handling_invalid_none() {
        let encrypted = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==".to_string();
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::InvalidNonce);
        let encrypted = "AAA^AAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==".to_string();
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::InvalidNonce);
    }

    #[test]
    fn encrypted_string_handling_invalid_data() {
        let encrypted = "AAAAAAAAAAAAAAAA SGVsbG8s%HdvcmxkIQ==".to_string();
        let encrypted = Encrypted::try_from(encrypted);
        assert_eq!(encrypted.unwrap_err(), ParseError::InvalidData);
    }
}
