// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Contains helper for encryption.
use chacha20::cipher::generic_array::GenericArray;
use chacha20::cipher::typenum::{U12, U32};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::base::IndexedByteStorage;

#[derive(Clone, Debug)]
struct Encrypted {
    /// The first 12 bytes of the encrypted data are the nonce.
    ///
    /// They are combined to implement AsRef<[u8]> for Encrypted.
    data_and_nonce: Vec<u8>,
}

impl Encrypted {
    fn new(nonce: [u8; 12], mut data: Vec<u8>) -> Self {
        data.splice(..0, nonce.iter().cloned());
        Self {
            data_and_nonce: data,
        }
    }

    fn data(&self) -> &[u8] {
        &self.data_and_nonce[12..]
    }

    fn nonce(&self) -> &GenericArray<u8, U12> {
        self.data_and_nonce[..12].into()
    }
}

impl From<Vec<u8>> for Encrypted {
    fn from(data_and_nonce: Vec<u8>) -> Self {
        Self { data_and_nonce }
    }
}

impl AsRef<[u8]> for Encrypted {
    fn as_ref(&self) -> &[u8] {
        self.data_and_nonce.as_ref()
    }
}

/// A ChaCha20 index file storer.
///
/// Encrypts and decrypts the index file using ChaCha20 and a given password.
#[derive(Clone, Debug)]
pub struct ChaCha20IndexFileStorer<T> {
    store: T,
    key: Key,
}

#[derive(Clone, Debug)]
/// Key to used for encryption
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

impl From<&String> for Key {
    fn from(s: &String) -> Self {
        Key::from(s.as_str())
    }
}
impl From<String> for Key {
    fn from(s: String) -> Self {
        Key::from(s.as_str())
    }
}
impl<T> ChaCha20IndexFileStorer<T> {
    /// Creates a new instance.
    pub fn new<K>(store: T, key: K) -> Self
    where
        K: Into<Key>,
    {
        Self {
            store,
            key: key.into(),
        }
    }

    fn encrypt(key: &Key, mut data: Vec<u8>) -> Encrypted {
        let mut nonce = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce);
        let Key(key) = key;
        let mut cipher = ChaCha20::new(key, &nonce.into());
        cipher.apply_keystream(&mut data);
        Encrypted::new(nonce, data)
    }

    fn decrypt(key: &Key, encrypted: &Encrypted) -> Vec<u8> {
        let mut data = encrypted.data().to_vec();
        let Key(key) = key;
        let mut cipher = ChaCha20::new(key, encrypted.nonce());
        cipher.apply_keystream(&mut data);
        data.to_vec()
    }
}

impl<S> IndexedByteStorage for ChaCha20IndexFileStorer<S>
where
    S: IndexedByteStorage,
{
    fn put<T>(&mut self, key: &str, data: T) -> Result<(), crate::base::Error>
    where
        T: AsRef<[u8]>,
    {
        let encrypted = Self::encrypt(&self.key, data.as_ref().to_vec());
        self.store.put(key, encrypted)
    }

    fn append_all<T>(&mut self, key: &str, data: &[T]) -> Result<(), crate::base::Error>
    where
        T: AsRef<[u8]>,
    {
        let data = data
            .iter()
            .map(|d| Self::encrypt(&self.key, d.as_ref().to_vec()))
            .collect::<Vec<_>>();
        self.store.append_all(key, &data)
    }

    fn remove(&mut self, key: &str) -> Result<(), crate::base::Error> {
        self.store.remove(key)
    }

    fn indices(&self, key: &str) -> Result<Vec<crate::base::Index>, crate::base::Error> {
        self.store.indices(key)
    }

    fn by_indices<T>(
        &self,
        key: &str,
        indices: &[crate::base::Index],
    ) -> Result<Vec<T>, crate::base::Error>
    where
        T: TryFrom<Vec<u8>>,
    {
        let encrypted = self.store.by_indices::<Encrypted>(key, indices)?;
        Ok(encrypted
            .into_iter()
            .map(|e| Self::decrypt(&self.key, &e).try_into())
            .filter_map(Result::ok)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::base::{CachedIndexFileStorer, Range};

    use super::*;
    const BASE: &str = "/tmp/openvasd/unittest";

    #[test]
    fn append_all() {
        let key = "test_crypto_append_all";
        let amount = 1000;
        fn random_data() -> Vec<u8> {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            let mut data = vec![0; 1024];
            rng.fill_bytes(&mut data);
            data
        }
        let mut data = Vec::with_capacity(amount);
        for _ in 0..amount {
            data.push(random_data());
        }

        let store = CachedIndexFileStorer::init(BASE).unwrap();
        let mut store = ChaCha20IndexFileStorer::new(store, Key::default());
        store.put(key, "Hello World".as_bytes()).unwrap();
        store.append_all(key, &data).unwrap();
        let results_all: Vec<Vec<u8>> = store.by_range(key, Range::All).unwrap();
        assert_eq!(results_all.len(), amount + 1);
        assert_eq!(results_all[0], "Hello World".as_bytes());
        let results: Vec<Vec<u8>> = store.by_range(key, Range::Between(1, amount + 1)).unwrap();
        let results_from: Vec<Vec<u8>> = store.by_range(key, Range::From(1)).unwrap();
        let results_until: Vec<Vec<u8>> = store.by_range(key, Range::Until(amount + 1)).unwrap();
        assert_eq!(results_until[0], results_all[0]);

        for i in 0..amount {
            assert_eq!(results[i], data[i]);
            assert_eq!(results[i], results_from[i]);
            // include the first element
            assert_eq!(results[i], results_until[i + 1]);
            assert_eq!(results[i], results_all[i + 1]);
        }
        store.remove(key).unwrap();
    }

    #[test]
    fn create_on_append() {
        let key = "create_crypto_on_append";
        let store = CachedIndexFileStorer::init(BASE).unwrap();
        let mut store = ChaCha20IndexFileStorer::new(store, Key::default());
        store.append(key, "Hello World".as_bytes()).unwrap();
        let results: Vec<Vec<u8>> = store.by_range(key, Range::All).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Hello World".as_bytes());
        store.remove(key).unwrap();
    }
}
