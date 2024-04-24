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
use nasl_builtin_utils::error::FunctionErrorKind;

use crate::NaslFunction;
use nasl_builtin_utils::{Context, Register};
use nasl_syntax::NaslValue;

use super::{get_data, get_iv, get_key, get_len, Crypt};

fn ctr<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FunctionErrorKind>
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
fn aes128_ctr_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
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
fn aes128_ctr_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes128>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes192_ctr_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
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
fn aes192_ctr_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes192>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes256_ctr_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
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
fn aes256_ctr_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes256>(register, Crypt::Decrypt)
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_ctr_encrypt" => Some(aes128_ctr_encrypt),
        "aes128_ctr_decrypt" => Some(aes128_ctr_decrypt),
        "aes192_ctr_encrypt" => Some(aes192_ctr_encrypt),
        "aes192_ctr_decrypt" => Some(aes192_ctr_decrypt),
        "aes256_ctr_encrypt" => Some(aes256_ctr_encrypt),
        "aes256_ctr_decrypt" => Some(aes256_ctr_decrypt),
        _ => None,
    }
}
