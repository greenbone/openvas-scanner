// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{
        BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
        KeyIvInit,
        block_padding::{NoPadding, ZeroPadding},
    },
};
use blowfish::Blowfish;
use cbc::{Decryptor, Encryptor};

use crate::nasl::prelude::*;

use super::Crypt;

/// Base function for en- and decrypting Cipher Block Chaining (CBC) mode
fn cbc<D>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
    crypt: Crypt,
) -> Result<NaslValue, FnError>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Mode Encrypt or Decrypt
    match crypt {
        Crypt::Encrypt => {
            let res = Encryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(encryptor) => Ok(encryptor.encrypt_padded_vec_mut::<ZeroPadding>(data).into()),
                Err(e) => Err(ArgumentError::WrongArgument(e.to_string()).into()),
            }
        }
        Crypt::Decrypt => {
            // length for encrypted data
            let len = len.unwrap_or(data.len());

            // len should not be more than the length of the data
            if len > data.len() {
                return Err(ArgumentError::wrong_argument(
                    "len",
                    format!("<={:?}", data.len()).as_str(),
                    len.to_string().as_str(),
                )
                .into());
            }
            let res = Decryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(decryptor) => Ok(decryptor
                    .decrypt_padded_vec_mut::<NoPadding>(data)
                    .map_err(|e| ArgumentError::WrongArgument(e.to_string()))?[..len]
                    .to_vec()
                    .into()),
                Err(e) => Err(ArgumentError::WrongArgument(e.to_string()).into()),
            }
        }
    }
}

/// NASL function to encrypt data with aes128 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function(named(key, iv, data))]
fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    cbc::<Aes128>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes128 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function(named(key, iv, data, len))]
fn aes128_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    cbc::<Aes128>(key, iv, data, len, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function(named(key, iv, data))]
fn aes192_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    cbc::<Aes192>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes192 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function(named(key, iv, data, len))]
fn aes192_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    cbc::<Aes192>(key, iv, data, len, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function(named(key, iv, data))]
fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    cbc::<Aes256>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes256 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function(named(key, iv, data, len))]
fn aes256_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    cbc::<Aes256>(key, iv, data, len, Crypt::Decrypt)
}

/// NASL function to decrypt data with triple des ede cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 8 bytes. The last block is filled so it also has 8 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 8 bytes
/// - The key must have a length of 24 bytes
#[nasl_function(named(key, iv, data))]
fn des_ede_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    cbc::<des::TdesEde3>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with blowfish cbc.
///
/// Encrypt the plaintext data using the blowfish algorithm in CBC mode
/// with the key key and the initialization vector iv.  The key must be
/// 16 bytes long.  The iv must be at least 8 bytes long. Data must be a
/// multiple of 8 bytes long.
///
/// The return value is an array a with a[0] being the encrypted data and
/// a[1] the new initialization vector to use for the next part of the
/// data.
#[nasl_function(named(key, iv, data))]
fn bf_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    cbc::<Blowfish>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with blowfish cbc.
///
/// Decrypt the cipher text data using the blowfish algorithm in CBC mode
/// with the key key and the initialization vector iv.  The key must be
/// 16 bytes long.  The iv must be at least 8 bytes long.  data must be a
/// multiple of 8 bytes long.
///
/// The return value is an array a with a[0] being the plaintext data
/// and a[1] the new initialization vector to use for the next part of
/// the data.
#[nasl_function(named(key, iv, data))]
fn bf_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    cbc::<Blowfish>(key, iv, data, None, Crypt::Decrypt)
}

pub struct Cbc;

function_set! {
    Cbc,
    (
        aes128_cbc_encrypt,
        aes128_cbc_decrypt,
        aes192_cbc_encrypt,
        aes192_cbc_decrypt,
        aes256_cbc_encrypt,
        aes256_cbc_decrypt,
        bf_cbc_encrypt,
        bf_cbc_decrypt,
        des_ede_cbc_encrypt,
    )
}
