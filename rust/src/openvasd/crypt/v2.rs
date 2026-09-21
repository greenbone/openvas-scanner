// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! V2 encryption method.
//!
//! * Key Derivation: Argon2id version 19 with default parameters and a 16 byte salt
//! * Encryption: ChaCha20Poly1305
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use rand::{self, Rng};

use super::Encrypted;

const VERSION: u8 = 2;

#[derive(Clone, Debug, Default)]
pub struct V2Crypter {
    pub(super) key: [u8; 32],
}

impl V2Crypter {
    pub fn new(keyphrase: &[u8], salt: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
        hasher.hash_password_into(keyphrase, salt, &mut key)?;
        Ok(V2Crypter { key })
    }

    pub(super) fn encrypt_sync(key: &[u8; 32], data: Vec<u8>) -> anyhow::Result<Encrypted> {
        let mut nonce = [0u8; 12];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new(key.into());
        let data = cipher.encrypt(&nonce.into(), data.as_slice())?;

        Ok(Encrypted {
            version: VERSION,
            nonce,
            data,
        })
    }

    pub(super) fn decrypt_sync(key: &[u8; 32], encrypted: &Encrypted) -> anyhow::Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        cipher
            .decrypt(&encrypted.nonce.into(), encrypted.data.as_slice())
            .map_err(|e| e.into())
    }
}
