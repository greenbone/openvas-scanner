// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::{
    cipher::{
        BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyIvInit, StreamCipher,
        StreamCipherSeek,
    },
    Aes128, Aes192, Aes256,
};
use digest::typenum::U16;

use crate::nasl::prelude::*;

use super::{get_data, get_iv, get_key, get_len, Crypt};

fn ctr<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FnError>
where
    D: BlockSizeUser<BlockSize = U16>
        + aes::cipher::KeyInit
        + BlockCipher
        + BlockEncrypt
        + BlockDecrypt,
{
    // Get data
    let key = get_key(register)?;
    let data = get_data(register)?;
    let data_len = data.len();
    let iv = get_iv(register)?;
    let len = match get_len(register)? {
        Some(x) => x,
        None => data_len,
    };

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
#[nasl_function]
fn aes128_ctr_encrypt(register: &Register) -> Result<NaslValue, FnError> {
    ctr::<Aes128>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes128 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function]
fn aes128_ctr_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    ctr::<Aes128>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function]
fn aes192_ctr_encrypt(register: &Register) -> Result<NaslValue, FnError> {
    ctr::<Aes192>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes192 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function]
fn aes192_ctr_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    ctr::<Aes192>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function]
fn aes256_ctr_encrypt(register: &Register) -> Result<NaslValue, FnError> {
    ctr::<Aes256>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes256 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
#[nasl_function]
fn aes256_ctr_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    ctr::<Aes256>(register, Crypt::Decrypt)
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
