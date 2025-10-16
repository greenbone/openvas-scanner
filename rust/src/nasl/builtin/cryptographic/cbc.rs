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
use cbc::{Decryptor, Encryptor};

use crate::nasl::prelude::*;

use super::{Crypt, get_data, get_iv, get_key, get_len};

/// Base function for en- and decrypting Cipher Block Chaining (CBC) mode
fn cbc<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FnError>
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
                Err(e) => Err(ArgumentError::WrongArgument(e.to_string()).into()),
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
#[nasl_function]
fn aes128_cbc_encrypt(register: &Register) -> Result<NaslValue, FnError> {
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
#[nasl_function]
fn aes128_cbc_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    cbc::<Aes128>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function]
fn aes192_cbc_encrypt(register: &Register) -> Result<NaslValue, FnError> {
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
#[nasl_function]
fn aes192_cbc_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    cbc::<Aes192>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
#[nasl_function]
fn aes256_cbc_encrypt(register: &Register) -> Result<NaslValue, FnError> {
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
#[nasl_function]
fn aes256_cbc_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    cbc::<Aes256>(register, Crypt::Decrypt)
}

/// NASL function to decrypt data with triple des ede cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 8 bytes. The last block is filled so it also has 8 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 8 bytes
/// - The key must have a length of 24 bytes
#[nasl_function]
fn des_ede_cbc_encrypt(register: &Register) -> Result<NaslValue, FnError> {
    cbc::<des::TdesEde3>(register, Crypt::Encrypt)
}

pub struct AesCbc;

function_set! {
    AesCbc,
    (
        aes128_cbc_encrypt,
        aes128_cbc_decrypt,
        aes192_cbc_encrypt,
        aes192_cbc_decrypt,
        aes256_cbc_encrypt,
        aes256_cbc_decrypt,
        des_ede_cbc_encrypt,
    )
}
