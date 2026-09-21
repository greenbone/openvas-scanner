// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! V1 encryption method.
//!
//! * Key Derivation: PBKDF2 with SHA256, 8000 turns and the salt of 0x0000000000000000
//! * Encryption: ChaCha20
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use super::Encrypted;

#[derive(Clone, Debug, Default)]
pub struct V1Crypter {
    pub(super) key: [u8; 32],
}

impl V1Crypter {
    pub fn new(keyphrase: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        let salt = [0u8; 8];
        pbkdf2_hmac::<Sha256>(keyphrase, &salt, 8000, &mut key);
        Ok(Self { key })
    }

    pub(super) fn decrypt_sync(key: &[u8; 32], encrypted: &Encrypted) -> anyhow::Result<Vec<u8>> {
        let mut data = encrypted.data.clone();
        let mut cipher = ChaCha20::new(key.into(), &encrypted.nonce.into());
        cipher.apply_keystream(&mut data);
        Ok(data)
    }
}
