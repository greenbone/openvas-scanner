// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// FnError::GeneralError
use crate::nasl::prelude::*;
use aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit},
};
use aes_gcm::{
    AesGcm,
    aead::{Aead, Payload},
};
use digest::typenum::{U12, U16};

use super::{Crypt, CryptographicError};

fn gcm<D>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
    aad: Option<&[u8]>,
    crypt: Crypt,
) -> Result<NaslValue, FnError>
where
    D: BlockSizeUser<BlockSize = U16>
        + aes::cipher::KeyInit
        + BlockCipher
        + BlockEncrypt
        + BlockDecrypt,
{
    let cipher = AesGcm::<D, U12>::new(key.into());
    let aad = aad.unwrap_or_default();

    let mut payload = Payload { msg: data, aad };

    let res = match crypt {
        Crypt::Encrypt => {
            if !data.len().is_multiple_of(16) {
                let blocks_len = data.len() + 16 - data.len() % 16;

                let mut vec = data.to_vec();
                while vec.len() < blocks_len {
                    vec.push(0);
                }
                payload.msg = vec.as_slice();
                cipher.encrypt(iv.into(), payload)
            } else {
                cipher.encrypt(iv.into(), payload)
            }
        }
        Crypt::Decrypt => cipher.decrypt(iv.into(), payload),
    };
    match res {
        Ok(x) => match crypt {
            Crypt::Decrypt => match len {
                Some(y) => Ok(x[..y].to_vec().into()),
                None => Ok(x.into()),
            },
            Crypt::Encrypt => Ok(x.into()),
        },
        Err(_) => Err(CryptographicError::InsufficientBufferSize.into()),
    }
}

/// NASL function to encrypt data with aes128 gcm.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
#[nasl_function(named(key, iv, data))]
fn aes128_gcm_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    gcm::<Aes128>(key, iv, data, None, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with aes128 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects 4 named arguments key, data, iv and aad either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
#[nasl_function(named(key, iv, data, aad))]
fn aes128_gcm_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes128>(key, iv, data, None, aad, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes128 gcm.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
#[nasl_function(named(key, iv, data, len))]
fn aes128_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes128>(key, iv, data, len, None, Crypt::Decrypt)
}

/// NASL function to decrypt data with aes128 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
#[nasl_function(named(key, iv, data, len, aad))]
fn aes128_gcm_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes128>(key, iv, data, len, aad, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 gcm.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
#[nasl_function(named(key, iv, data))]
fn aes192_gcm_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    gcm::<Aes192>(key, iv, data, None, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with aes192 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects 4 named arguments key, data, iv and aad either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
#[nasl_function(named(key, iv, data, aad))]
fn aes192_gcm_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes192>(key, iv, data, None, aad, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes192 gcm.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
#[nasl_function(named(key, iv, data, len))]
fn aes192_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes192>(key, iv, data, len, None, Crypt::Decrypt)
}

/// NASL function to decrypt data with aes192 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
#[nasl_function(named(key, iv, data, len, aad))]
fn aes192_gcm_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes192>(key, iv, data, len, aad, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 gcm.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
#[nasl_function(named(key, iv, data))]
fn aes256_gcm_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    gcm::<Aes256>(key, iv, data, None, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with aes256 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects 4 named arguments key, data, iv and aad either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
#[nasl_function(named(key, iv, data, aad))]
fn aes256_gcm_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes256>(key, iv, data, None, aad, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes256 gcm.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
#[nasl_function(named(key, iv, data, len))]
fn aes256_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes256>(key, iv, data, len, None, Crypt::Decrypt)
}

/// NASL function to decrypt data with aes256 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
#[nasl_function(named(key, iv, data, len, aad))]
fn aes256_gcm_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    gcm::<Aes256>(key, iv, data, len, aad, Crypt::Decrypt)
}

pub struct AesGcmFns;

function_set! {
    AesGcmFns,
    (
        aes128_gcm_encrypt,
        aes128_gcm_encrypt_auth,
        aes128_gcm_decrypt,
        aes128_gcm_decrypt_auth,
        aes192_gcm_encrypt,
        aes192_gcm_encrypt_auth,
        aes192_gcm_decrypt,
        aes192_gcm_decrypt_auth,
        aes256_gcm_encrypt,
        aes256_gcm_encrypt_auth,
        aes256_gcm_decrypt,
        aes256_gcm_decrypt_auth,
    )
}
