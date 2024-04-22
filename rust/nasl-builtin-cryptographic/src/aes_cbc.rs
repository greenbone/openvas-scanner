// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::{
    cipher::{
        block_padding::{NoPadding, ZeroPadding},
        BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
        KeyIvInit,
    },
    Aes128, Aes192, Aes256,
};
use cbc::{Decryptor, Encryptor};

use crate::NaslFunction;
use nasl_builtin_utils::error::FunctionErrorKind;
use nasl_builtin_utils::{Context, Register};
use nasl_syntax::NaslValue;

use super::{get_data, get_iv, get_key, get_len, Crypt};

/// Base function for en- and decrypting Cipher Block Chaining (CBC) mode
fn cbc<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FunctionErrorKind>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Get Arguments
    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;

    // Mode Encrypt or Decrypt
    match crypt {
        Crypt::Encrypt => {
            let res = Encryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(encryptor) => Ok(encryptor.encrypt_padded_vec_mut::<ZeroPadding>(data).into()),
                Err(e) => Err(FunctionErrorKind::WrongArgument(e.to_string())),
            }
        }
        Crypt::Decrypt => {
            // length for encrypted data
            let len = match get_len(register)? {
                Some(x) => x,
                None => data.len(),
            };

            // len should not be more than the length of the data
            if len > data.len() {
                return Err((
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
                    .map_err(|e| FunctionErrorKind::WrongArgument(e.to_string()))?[..len]
                    .to_vec()
                    .into()),
                Err(e) => Err(FunctionErrorKind::WrongArgument(e.to_string())),
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
fn aes128_cbc_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    cbc::<Aes128>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes128 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes128_cbc_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    cbc::<Aes128>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes192_cbc_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    cbc::<Aes192>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes192 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes192_cbc_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    cbc::<Aes192>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes256_cbc_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    cbc::<Aes256>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes256 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes256_cbc_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    cbc::<Aes256>(register, Crypt::Decrypt)
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_cbc_encrypt" => Some(aes128_cbc_encrypt),
        "aes128_cbc_decrypt" => Some(aes128_cbc_decrypt),
        "aes192_cbc_encrypt" => Some(aes192_cbc_encrypt),
        "aes192_cbc_decrypt" => Some(aes192_cbc_decrypt),
        "aes256_cbc_encrypt" => Some(aes256_cbc_encrypt),
        "aes256_cbc_decrypt" => Some(aes256_cbc_decrypt),
        _ => None,
    }
}
