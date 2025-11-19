// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{
        BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyIvInit, StreamCipher,
        StreamCipherSeek,
    },
};
use digest::typenum::U16;

use crate::nasl::prelude::*;

use super::Crypt;

fn ctr<D>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
    crypt: Crypt,
) -> Result<NaslValue, FnError>
where
    D: BlockSizeUser<BlockSize = U16>
        + aes::cipher::KeyInit
        + BlockCipher
        + BlockEncrypt
        + BlockDecrypt,
{
    let len = len.unwrap_or(data.len());

    let mut cipher = ctr::Ctr64BE::<D>::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    // Mode Encrypt or Decrypt
    match crypt {
        Crypt::Encrypt => {
            cipher.apply_keystream(&mut buf);
            Ok(buf.to_vec().into())
        }
        Crypt::Decrypt => {
            cipher.seek(0u32);
            cipher.apply_keystream(&mut buf);
            Ok(buf[..len].to_vec().into())
        }
    }
}

/// NASL function to encrypt data with aes128 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function(named(key, iv, data))]
fn aes128_ctr_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    ctr::<Aes128>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes128 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function(named(key, iv, data, len))]
fn aes128_ctr_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ctr::<Aes128>(key, iv, data, len, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function(named(key, iv, data))]
fn aes192_ctr_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    ctr::<Aes192>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes192 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function(named(key, iv, data, len))]
fn aes192_ctr_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ctr::<Aes192>(key, iv, data, len, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function(named(key, iv, data))]
fn aes256_ctr_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    ctr::<Aes256>(key, iv, data, None, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes256 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function(named(key, iv, data, len))]
fn aes256_ctr_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ctr::<Aes256>(key, iv, data, len, Crypt::Decrypt)
}

pub struct AesCtr;

function_set! {
    AesCtr,
    (
        aes128_ctr_encrypt,
        aes128_ctr_decrypt,
        aes192_ctr_encrypt,
        aes192_ctr_decrypt,
        aes256_ctr_encrypt,
        aes256_ctr_decrypt,
    )
}
