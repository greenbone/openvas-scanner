// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::Display;

use async_trait::async_trait;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use pbkdf2::pbkdf2_hmac;
use rand::{self, RngCore};
use sha2::Sha256;

#[derive(Clone, Debug)]
pub struct Key(GenericArray<u8, U32>);

impl Default for Key {
    fn default() -> Self {
        let mut key = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        Key(key.into())
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        let mut key = [0u8; 32];
        // we currently don't need a salt as we only have one key
        let salt = [0u8; 8];
        pbkdf2_hmac::<Sha256>(s.as_bytes(), &salt, 8000, &mut key);
        Key(key.into())
    }
}

impl From<String> for Key {
    fn from(s: String) -> Self {
        Key::from(s.as_str())
    }
}

#[async_trait]
pub trait Crypt {
    async fn encrypt(&self, data: Vec<u8>) -> Encrypted;
    fn encrypt_sync(&self, data: Vec<u8>) -> Encrypted;

    async fn decrypt(&self, encrypted: Encrypted) -> Vec<u8>;
    fn decrypt_sync(&self, encrypted: &Encrypted) -> Vec<u8>;
}

#[derive(Clone, Debug, Default)]
pub struct ChaCha20Crypt {
    key: Key,
}

impl ChaCha20Crypt {
    fn encrypt_sync(key: &Key, mut data: Vec<u8>) -> Encrypted {
        let mut nonce = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce);
        let Key(key) = key;
        let mut cipher = ChaCha20::new(key, &nonce.into());
        cipher.apply_keystream(&mut data);
        Encrypted { nonce, data }
    }

    fn decrypt_sync(key: &Key, encrypted: &Encrypted) -> Vec<u8> {
        let mut data = encrypted.data.clone();
        let Key(key) = key;
        let mut cipher = ChaCha20::new(key, &encrypted.nonce.into());
        cipher.apply_keystream(&mut data);
        data
    }
}

#[async_trait]
impl Crypt for ChaCha20Crypt {
    async fn encrypt(&self, data: Vec<u8>) -> Encrypted {
        let key = self.key.clone();
        tokio::task::spawn_blocking(move || Self::encrypt_sync(&key, data))
            .await
            .unwrap()
    }

    fn encrypt_sync(&self, data: Vec<u8>) -> Encrypted {
        Self::encrypt_sync(&self.key, data)
    }

    async fn decrypt(&self, encrypted: Encrypted) -> Vec<u8> {
        let key = self.key.clone();
        tokio::task::spawn_blocking(move || Self::decrypt_sync(&key, &encrypted))
            .await
            .unwrap()
    }

    fn decrypt_sync(&self, encrypted: &Encrypted) -> Vec<u8> {
        Self::decrypt_sync(&self.key, encrypted)
    }
}

#[derive(Clone, Debug)]
pub struct Encrypted {
    nonce: [u8; 12],
    data: Vec<u8>,
}

impl Display for Encrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::{display::Base64Display, engine::general_purpose::STANDARD};

        let nonce = Base64Display::new(&self.nonce, &STANDARD);
        let data = Base64Display::new(&self.data, &STANDARD);
        write!(f, "{} {}", nonce, data)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    MissingNonce,
    MissingData,
    InvalidNonce,
    InvalidData,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseError::*;
        match self {
            MissingNonce => write!(f, "missing nonce"),
            MissingData => write!(f, "missing data"),
            InvalidNonce => write!(f, "invalid nonce"),
            InvalidData => write!(f, "invalid data"),
        }
    }
}

impl std::error::Error for ParseError {}

impl TryFrom<&str> for Encrypted {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        use base64::{engine::general_purpose, Engine as _};
        let mut parts = s.split_whitespace();
        let decode = |s: &str, e: ParseError| {
            general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(|_| e)
        };
        let nonce = parts
            .next()
            .map(|nonce| decode(nonce, ParseError::InvalidNonce))
            .ok_or(ParseError::MissingNonce)??;
        let data = parts
            .next()
            .map(|nonce| decode(nonce, ParseError::InvalidData))
            .ok_or(ParseError::MissingData)??;
        Ok(Encrypted {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chacha20_encrypt_decrypt() {
        let data = b"Hello, world!".to_vec();
        let encryptor = ChaCha20Crypt::default();
        let encrypted = encryptor.encrypt(data.clone()).await;
        let decrypted = encryptor.decrypt(encrypted).await;
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn encrypted_string_handling() {
        let encrypted = Encrypted {
            nonce: [0u8; 12],
            data: b"Hello, world!".to_vec(),
        };
        let encrypted = encrypted.to_string();
        assert_eq!(encrypted, "AAAAAAAAAAAAAAAA SGVsbG8sIHdvcmxkIQ==");
        let encrypted = Encrypted::try_from(encrypted).unwrap();
        assert_eq!(encrypted.nonce, [0u8; 12]);
        assert_eq!(encrypted.data, b"Hello, world!".to_vec());
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
